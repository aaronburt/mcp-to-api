import hashlib
import io
import json
import logging
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from gateway.audit import AuditLogger
from gateway.cli import main, token_main
from gateway.config import load_config_from_dict
from gateway.gateway import GatewayCore
from gateway.server import create_http_app


class TestCliAndExtras(unittest.IsolatedAsyncioTestCase):
    def test_token_cli_and_check_cli(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = token_main(["--name", "hermes", "--acls", "proxmox-audit"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        lines = out.strip().splitlines()
        raw_token = lines[0].split("token: ", 1)[1].strip()
        expected_hash = "sha256:" + hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        self.assertIn(expected_hash, out)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            secret_file = tmp_path / "tok"
            secret_file.write_text("secret-abc", encoding="utf-8")
            cfg_file = tmp_path / "gateway.yaml"
            cfg_file.write_text(
                f"""
services:
  proxmox:
    url: https://pve.lan:8006/api2/json
    tls:
      verify: false
    auth:
      type: header
      header: Authorization
      value: "PVEAPIToken=${{env:PVE_TOKEN_ID}}=${{file:{secret_file.as_posix()}}}"
acls:
  proxmox-audit:
    proxmox:
      GET: [/version]
tokens:
  hermes:
    hash: {expected_hash}
    acls: [proxmox-audit]
""",
                encoding="utf-8",
            )
            check_buf = io.StringIO()
            with patch.dict(os.environ, {"PVE_TOKEN_ID": "audit@pve!gateway"}):
                with redirect_stdout(check_buf):
                    rc_check = main(["--config", str(cfg_file), "--check"])
            self.assertEqual(rc_check, 0)
            self.assertIn("1 service(s), 1 token(s)", check_buf.getvalue())

            rc_missing = main(["--config", str(tmp_path / "missing.yaml"), "--check"])
            self.assertEqual(rc_missing, 2)

            with patch.dict(os.environ, {"PVE_TOKEN_ID": "audit@pve!gateway"}):
                with patch("gateway.cli.uvicorn.run") as mock_run:
                    rc_run = main(["--config", str(cfg_file), "--port", "0"])
            self.assertEqual(rc_run, 0)
            mock_run.assert_called_once()
            self.assertEqual(mock_run.call_args.kwargs["port"], 0)

    async def test_rate_limit_query_auth_form_post_and_host_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret_file = Path(tmp) / "tok"
            secret_file.write_text("query-secret-999", encoding="utf-8")
            audit_stream = io.StringIO()
            raw = {
                "server": {
                    "allowed_hosts": ["gateway.lan:*"],
                },
                "services": {
                    "svc": {
                        "url": "https://api.lan/v1",
                        "rate_limit": "2/min",
                        "tls": {"verify": False},
                        "auth": {
                            "type": "query",
                            "param": "apikey",
                            "value": f"${{file:{secret_file.as_posix()}}}",
                        },
                    }
                },
                "acls": {
                    "rw": {
                        "svc": {
                            "GET": ["/items"],
                            "POST": ["/items"],
                        }
                    }
                },
                "tokens": {
                    "hermes": {
                        "hash": "sha256:" + hashlib.sha256(b"tok1").hexdigest(),
                        "acls": ["rw"],
                    }
                },
            }
            cfg = load_config_from_dict(raw)
            seen_requests: list[httpx2.Request] = []

            def mock_upstream(request: httpx2.Request) -> httpx2.Response:
                seen_requests.append(request)
                return httpx2.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json={"ok": True},
                )

            audit_logger = AuditLogger(stdout=True, redactor=cfg.redactor, stream=audit_stream)
            core = GatewayCore(
                cfg,
                audit_logger=audit_logger,
                transports={"svc": httpx2.MockTransport(mock_upstream)},
            )
            app = create_http_app(core)
            starlette_app = app._app
            async with starlette_app.router.lifespan_context(starlette_app):
                transport = httpx2.ASGITransport(app=app)
                async with httpx2.AsyncClient(transport=transport, base_url="http://evil.lan:8080") as bad_client:
                    bad_host = await bad_client.post(
                        "/mcp",
                        headers={"Authorization": "Bearer tok1"},
                        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                    )
                    self.assertEqual(bad_host.status_code, 421)

                    bad_port_host = await bad_client.post(
                        "/mcp",
                        headers={"Host": "gateway.lan:evil", "Authorization": "Bearer tok1"},
                        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                    )
                    self.assertEqual(bad_port_host.status_code, 421)

                    bare_host = await bad_client.post(
                        "/mcp",
                        headers={"Host": "gateway.lan"},
                        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                    )
                    self.assertEqual(bare_host.status_code, 401)

                    upper_host = await bad_client.post(
                        "/mcp",
                        headers={"Host": "Gateway.LAN:8080"},
                        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                    )
                    self.assertEqual(upper_host.status_code, 401)

                http_client = httpx2.AsyncClient(
                    transport=transport,
                    headers={"Authorization": "Bearer tok1"},
                )
                async with http_client:
                    async with streamable_http_client(
                        "http://gateway.lan:8080/mcp",
                        http_client=http_client,
                    ) as (read_stream, write_stream):
                        async with ClientSession(read_stream, write_stream) as session:
                            await session.initialize()

                            res_list = await session.call_tool("list_services", {})
                            self.assertFalse(res_list.is_error)
                            self.assertEqual(json.loads(res_list.content[0].text)["services"][0]["name"], "svc")

                            res_reserved = await session.call_tool(
                                "http_request",
                                {
                                    "service": "svc",
                                    "method": "GET",
                                    "path": "/items",
                                    "query": {"APIKEY": "attacker"},
                                },
                            )
                            self.assertTrue(res_reserved.is_error)
                            self.assertIn("reserved", res_reserved.content[0].text)

                            self.assertFalse(logging.getLogger("httpx2").isEnabledFor(logging.INFO))
                            log_capture = io.StringIO()
                            handler = logging.StreamHandler(log_capture)
                            root_logger = logging.getLogger()
                            root_logger.addHandler(handler)
                            try:
                                res1 = await session.call_tool(
                                    "http_request",
                                    {
                                        "service": "svc",
                                        "method": "GET",
                                        "path": "/items",
                                        "query": {"page": 1},
                                    },
                                )
                            finally:
                                root_logger.removeHandler(handler)
                            self.assertNotIn("query-secret-999", log_capture.getvalue())
                            self.assertFalse(res1.is_error)
                            self.assertIn("apikey=query-secret-999", str(seen_requests[0].url))

                            res2 = await session.call_tool(
                                "http_request",
                                {
                                    "service": "svc",
                                    "method": "POST",
                                    "path": "/items",
                                    "body": {"k": "v"},
                                    "body_format": "form",
                                },
                            )
                            self.assertFalse(res2.is_error)
                            self.assertEqual(
                                seen_requests[1].headers["content-type"],
                                "application/x-www-form-urlencoded",
                            )

                            res3 = await session.call_tool(
                                "http_request",
                                {"service": "svc", "method": "GET", "path": "/items"},
                            )
                            self.assertTrue(res3.is_error)
                            self.assertIn("Rate limit exceeded", res3.content[0].text)


if __name__ == "__main__":
    unittest.main()
