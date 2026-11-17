import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from gateway.audit import AuditLogger
from gateway.config import load_config_from_dict
from gateway.gateway import GatewayCore
from gateway.server import create_http_app


def _sha256_prefixed(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


class TestMcpHttpEndToEnd(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.secret = "pve-super-secret-uuid-5555"
        secret_file = Path(self._tmp.name) / "pve_token"
        secret_file.write_text(self.secret, encoding="utf-8")

        self.hermes_token = "hermes-secret-bearer-token-0001"
        self.other_token = "other-secret-bearer-token-0002"
        self.audit_stream = io.StringIO()

        raw = {
            "services": {
                "proxmox": {
                    "url": "https://pve.lan:8006/api2/json",
                    "description": "Proxmox VE read-only audit",
                    "tls": {"verify": False},
                    "auth": {
                        "type": "header",
                        "header": "Authorization",
                        "value": f"PVEAPIToken=${{env:PVE_TOKEN_ID}}=${{file:{secret_file}}}",
                    },
                },
                "metrics": {
                    "url": "https://metrics.lan/api",
                    "tls": {"verify": False},
                    "auth": {"type": "bearer", "token": f"${{file:{secret_file}}}"},
                },
            },
            "acls": {
                "proxmox-audit": {
                    "proxmox": {
                        "GET": ["/version", "/nodes", "/nodes/*/status"],
                    }
                },
                "metrics-read": {
                    "metrics": {
                        "GET": ["/health"],
                    }
                },
            },
            "tokens": {
                "hermes": {
                    "hash": _sha256_prefixed(self.hermes_token),
                    "acls": ["proxmox-audit"],
                },
                "other": {
                    "hash": _sha256_prefixed(self.other_token),
                    "acls": ["metrics-read"],
                },
            },
        }
        with patch.dict(os.environ, {"PVE_TOKEN_ID": "audit@pve!gateway"}):
            self.cfg = load_config_from_dict(raw)

        def mock_pve(request: httpx2.Request) -> httpx2.Response:
            if request.url.path == "/api2/json/nodes/pve1/status":
                return httpx2.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json={"data": {"uptime": 4200, "cpu": 0.12}},
                )
            return httpx2.Response(404, json={"error": "not found"})

        def mock_metrics(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, json={"ok": True})

        self.audit_logger = AuditLogger(
            stdout=True,
            redactor=self.cfg.redactor,
            stream=self.audit_stream,
        )
        self.core = GatewayCore(
            self.cfg,
            audit_logger=self.audit_logger,
            transports={
                "proxmox": httpx2.MockTransport(mock_pve),
                "metrics": httpx2.MockTransport(mock_metrics),
            },
        )
        self.app = create_http_app(self.core)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    async def test_healthz_auth_origin_and_mcp_tool_isolation(self) -> None:
        starlette_app = self.app._app
        async with starlette_app.router.lifespan_context(starlette_app):
            transport = httpx2.ASGITransport(app=self.app)
            async with httpx2.AsyncClient(transport=transport, base_url="http://gateway.lan:8080") as raw_client:
                hz = await raw_client.get("/healthz")
                self.assertEqual(hz.status_code, 200)
                self.assertEqual(
                    hz.json(),
                    {"status": "ok", "config_loaded": True, "secrets_present": True},
                )
                self.assertNotIn("proxmox", hz.text)
                self.assertNotIn(self.secret, hz.text)

                unauth = await raw_client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
                self.assertEqual(unauth.status_code, 401)

                bad_tok = await raw_client.post(
                    "/mcp",
                    headers={"Authorization": "Bearer wrong-token"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                )
                self.assertEqual(bad_tok.status_code, 401)

                bad_origin = await raw_client.post(
                    "/mcp",
                    headers={
                        "Authorization": f"Bearer {self.hermes_token}",
                        "Origin": "https://evil.example",
                    },
                    json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                )
                self.assertEqual(bad_origin.status_code, 403)

            hermes_http = httpx2.AsyncClient(
                transport=transport,
                headers={"Authorization": f"Bearer {self.hermes_token}"},
            )
            async with hermes_http:
                async with streamable_http_client(
                    "http://gateway.lan:8080/mcp",
                    http_client=hermes_http,
                ) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        init_res = await session.initialize()
                        self.assertIsNotNone(init_res.instructions)
                        self.assertIn("Allowed Routes for `hermes`", init_res.instructions)
                        self.assertIn("GET /nodes/*/status", init_res.instructions)
                        self.assertNotIn("metrics", init_res.instructions)

                        resources = await session.list_resources()
                        self.assertIn("gateway://instructions.md", [str(r.uri) for r in resources.resources])
                        inst_doc = await session.read_resource("gateway://instructions.md")
                        inst_text = inst_doc.contents[0].text
                        self.assertIn("GET /nodes/*/status", inst_text)
                        self.assertNotIn("metrics", inst_text)

                        tools = await session.list_tools()
                        tool_names = sorted(t.name for t in tools.tools)
                        self.assertEqual(tool_names, ["http_request", "list_services"])

                        svc_res = await session.call_tool("list_services", {})
                        self.assertFalse(svc_res.is_error)
                        svc_json = json.loads(svc_res.content[0].text)
                        self.assertEqual([s["name"] for s in svc_json["services"]], ["proxmox"])

                        ok_res = await session.call_tool(
                            "http_request",
                            {
                                "service": "proxmox",
                                "method": "GET",
                                "path": "/nodes/pve1/status",
                            },
                        )
                        self.assertFalse(ok_res.is_error)
                        ok_payload = json.loads(ok_res.content[0].text)
                        self.assertEqual(ok_payload["status"], 200)
                        self.assertEqual(ok_payload["body"]["data"]["uptime"], 4200)

                        denied_res = await session.call_tool(
                            "http_request",
                            {
                                "service": "proxmox",
                                "method": "GET",
                                "path": "/nodes/pve1/qemu/100/config",
                            },
                        )
                        self.assertTrue(denied_res.is_error)
                        self.assertIn("not allowed for proxmox", denied_res.content[0].text)

                        ungranted_svc = await session.call_tool(
                            "http_request",
                            {
                                "service": "metrics",
                                "method": "GET",
                                "path": "/health",
                            },
                        )
                        self.assertTrue(ungranted_svc.is_error)
                        self.assertIn("not granted", ungranted_svc.content[0].text)

            other_http = httpx2.AsyncClient(
                transport=transport,
                headers={"Authorization": f"Bearer {self.other_token}"},
            )
            async with other_http:
                async with streamable_http_client(
                    "http://gateway.lan:8080/mcp",
                    http_client=other_http,
                ) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        other_init = await session.initialize()
                        self.assertIsNotNone(other_init.instructions)
                        self.assertIn("Allowed Routes for `other`", other_init.instructions)
                        self.assertIn("GET /health", other_init.instructions)
                        self.assertNotIn("proxmox", other_init.instructions)
                        other_doc = await session.read_resource("gateway://instructions.md")
                        self.assertIn("GET /health", other_doc.contents[0].text)
                        self.assertNotIn("proxmox", other_doc.contents[0].text)
                        other_svcs = await session.call_tool("list_services", {})
                        self.assertEqual(
                            [s["name"] for s in json.loads(other_svcs.content[0].text)["services"]],
                            ["metrics"],
                        )
                        denied_pve = await session.call_tool(
                            "http_request",
                            {
                                "service": "proxmox",
                                "method": "GET",
                                "path": "/version",
                            },
                        )
                        self.assertTrue(denied_pve.is_error)

                        bad_fmt = await session.call_tool(
                            "http_request",
                            {
                                "service": "metrics",
                                "method": "GET",
                                "path": "/health",
                                "body_format": "xml",
                            },
                        )
                        self.assertTrue(bad_fmt.is_error)
                        self.assertIn("body_format must be 'json' or 'form'", bad_fmt.content[0].text)

            async with httpx2.AsyncClient(transport=transport, base_url="http://gateway.lan:8080") as raw_client:
                long_unauth = await raw_client.post(
                    "/" + ("a" * 700),
                    json={"jsonrpc": "2.0", "id": 9, "method": "initialize"},
                )
                self.assertEqual(long_unauth.status_code, 401)

                dup_auth = await raw_client.post(
                    "/mcp",
                    headers=[
                        ("Authorization", f"Bearer {self.hermes_token}"),
                        ("Authorization", "Bearer extra"),
                    ],
                    json={"jsonrpc": "2.0", "id": 9, "method": "initialize"},
                )
                self.assertEqual(dup_auth.status_code, 401)

                dup_host = await raw_client.post(
                    "/mcp",
                    headers=[
                        ("Host", "gateway.lan:8080"),
                        ("Host", "evil.lan:8080"),
                        ("Authorization", f"Bearer {self.hermes_token}"),
                    ],
                    json={"jsonrpc": "2.0", "id": 9, "method": "initialize"},
                )
                self.assertEqual(dup_host.status_code, 421)

                dup_origin = await raw_client.post(
                    "/mcp",
                    headers=[
                        ("Origin", "https://allowed.example"),
                        ("Origin", "https://evil.example"),
                        ("Authorization", f"Bearer {self.hermes_token}"),
                    ],
                    json={"jsonrpc": "2.0", "id": 9, "method": "initialize"},
                )
                self.assertEqual(dup_origin.status_code, 403)

                init_resp = await raw_client.post(
                    "/mcp",
                    headers={
                        "Authorization": f"Bearer {self.hermes_token}",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {},
                            "clientInfo": {"name": "test", "version": "1"},
                        },
                    },
                )
                self.assertEqual(init_resp.status_code, 200)
                session_id = init_resp.headers.get("mcp-session-id")
                self.assertIsNotNone(session_id)
                hijack_resp = await raw_client.post(
                    "/mcp",
                    headers={
                        "Authorization": f"Bearer {self.other_token}",
                        "Accept": "application/json, text/event-stream",
                        "Mcp-Session-Id": session_id,
                    },
                    json={"jsonrpc": "2.0", "id": 11, "method": "tools/list"},
                )
                self.assertEqual(hijack_resp.status_code, 404)

        audit_text = self.audit_stream.getvalue()
        self.assertNotIn(self.hermes_token, audit_text)
        self.assertNotIn("wrong-token", audit_text)
        self.assertNotIn(self.secret, audit_text)
        records = [json.loads(line) for line in audit_text.strip().splitlines()]
        self.assertTrue(any(r["outcome"] == "unauthenticated" for r in records))
        self.assertTrue(any(r["agent"] == "hermes" and r["outcome"] == "ok" for r in records))
        self.assertTrue(
            any(r["agent"] == "other" and r["outcome"] == "denied" and r["denial_reason"] == "body_format must be 'json' or 'form'" for r in records)
        )
        long_record = next(r for r in records if r["outcome"] == "unauthenticated" and r["path"].startswith("/aaaa"))
        self.assertLessEqual(len(long_record["path"]), 512)


if __name__ == "__main__":
    unittest.main()
