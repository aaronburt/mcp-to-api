import asyncio
import datetime
import io
import json
import os
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from gateway.audit import AuditLogger
from gateway.config import load_config_from_dict
from gateway.gateway import GatewayCore


def _generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


class TestEgressAndGateway(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.secret = "a1b2c3d4-secret-uuid-9876"
        self.secret_file = Path(self._tmp.name) / "pve_token"
        self.secret_file.write_text(self.secret, encoding="utf-8")
        self.audit_stream = io.StringIO()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build_gateway(self, handler) -> GatewayCore:
        raw = {
            "defaults": {
                "rate_limit": "60/min",
                "connect_timeout": "2s",
                "timeout": "5s",
                "max_response": "512",
            },
            "services": {
                "proxmox": {
                    "url": "https://pve.lan:8006/api2/json",
                    "description": "Proxmox audit",
                    "notes": "Paths are relative to /api2/json",
                    "tls": {"verify": False},
                    "auth": {
                        "type": "header",
                        "header": "Authorization",
                        "value": f"PVEAPIToken=${{env:PVE_TOKEN_ID}}=${{file:{self.secret_file}}}",
                    },
                }
            },
            "acls": {
                "proxmox-audit": {
                    "proxmox": {
                        "GET": [
                            "/version",
                            "/cluster/resources",
                            "/cluster/tasks",
                            "/nodes",
                            "/nodes/*/status",
                            "/nodes/*/qemu",
                            "/access/users",
                        ]
                    }
                }
            },
            "tokens": {
                "hermes": {
                    "hash": "sha256:" + ("a" * 64),
                    "acls": ["proxmox-audit"],
                },
                "limited": {
                    "hash": "sha256:" + ("b" * 64),
                    "acls": ["proxmox-audit"],
                    "enabled": False,
                },
            },
        }
        with patch.dict(os.environ, {"PVE_TOKEN_ID": "audit@pve!gateway"}):
            cfg = load_config_from_dict(raw)
        audit_logger = AuditLogger(stdout=True, redactor=cfg.redactor, stream=self.audit_stream)
        return GatewayCore(
            cfg,
            audit_logger=audit_logger,
            transports={"proxmox": httpx2.MockTransport(handler)},
        )

    async def test_proxmox_audit_flow_scrubbing_redirects_and_truncation(self) -> None:
        seen_requests: list[httpx2.Request] = []

        def mock_pve(request: httpx2.Request) -> httpx2.Response:
            seen_requests.append(request)
            if request.url.path == "/api2/json/cluster/tasks":
                return httpx2.Response(
                    200,
                    headers={
                        "Content-Type": "application/json",
                        "Set-Cookie": "PVEAuthCookie=dontleak",
                        "X-Internal-Secret": self.secret,
                    },
                    json={
                        "data": [
                            {"user": "audit@pve!gateway", "echoed": self.secret},
                        ]
                    },
                )
            if request.url.path == "/api2/json/nodes":
                return httpx2.Response(
                    302,
                    headers={
                        "Location": "https://evil.example/steal-token",
                        "Content-Type": "text/plain",
                    },
                    text="redirecting",
                )
            if request.url.path == "/api2/json/cluster/resources":
                return httpx2.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    text='{"data":"' + ("x" * 2000) + '"}',
                )
            if request.url.path == "/api2/json/version":
                return httpx2.Response(
                    404,
                    headers={"Content-Type": "application/json"},
                    json={"errors": "not found"},
                )
            raise AssertionError(f"Unexpected upstream path: {request.url.path}")

        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9"}):
            core = self._build_gateway(mock_pve)
            try:
                services = await core.list_services("hermes")
                self.assertEqual(len(services["services"]), 1)
                self.assertEqual(services["services"][0]["name"], "proxmox")
                self.assertIn("GET", services["services"][0]["allowed"])

                res = await core.http_request(
                    agent_name="hermes",
                    service="proxmox",
                    method="GET",
                    path="/cluster/tasks",
                    query={"limit": 5, "secret_query_val": "never-logged"},
                )
                self.assertFalse(res.is_error)
                self.assertIsNone(res.structured_content)
                self.assertEqual(len(seen_requests), 1)
                self.assertEqual(
                    str(seen_requests[0].url),
                    "https://pve.lan:8006/api2/json/cluster/tasks?limit=5&secret_query_val=never-logged",
                )
                self.assertEqual(
                    seen_requests[0].headers["authorization"],
                    f"PVEAPIToken=audit@pve!gateway={self.secret}",
                )
                payload = json.loads(res.content[0].text)
                self.assertEqual(payload["status"], 200)
                self.assertEqual(payload["headers"], {"content-type": "application/json"})
                self.assertEqual(payload["body"]["data"][0]["user"], "audit@pve!gateway")
                self.assertEqual(payload["body"]["data"][0]["echoed"], "[REDACTED]")

                redir = await core.http_request(
                    agent_name="hermes",
                    service="proxmox",
                    method="GET",
                    path="/nodes",
                )
                self.assertFalse(redir.is_error)
                redir_payload = json.loads(redir.content[0].text)
                self.assertEqual(redir_payload["status"], 302)
                self.assertNotIn("location", redir_payload["headers"])

                big = await core.http_request(
                    agent_name="hermes",
                    service="proxmox",
                    method="GET",
                    path="/cluster/resources",
                )
                self.assertFalse(big.is_error)
                big_payload = json.loads(big.content[0].text)
                self.assertTrue(big_payload["truncated"])
                self.assertLessEqual(len(big_payload["body"].encode("utf-8")), 512)

                upstream_404 = await core.http_request(
                    agent_name="hermes",
                    service="proxmox",
                    method="GET",
                    path="/version",
                )
                self.assertFalse(upstream_404.is_error)
                self.assertEqual(json.loads(upstream_404.content[0].text)["status"], 404)

                denied = await core.http_request(
                    agent_name="hermes",
                    service="proxmox",
                    method="GET",
                    path="/nodes/pve1/qemu/100/config",
                )
                self.assertTrue(denied.is_error)
                self.assertIn("not allowed for proxmox", denied.content[0].text)
                self.assertEqual(len(seen_requests), 4)

                disabled_res = await core.http_request(
                    agent_name="limited",
                    service="proxmox",
                    method="GET",
                    path="/version",
                )
                self.assertTrue(disabled_res.is_error)
                self.assertIn("not authorized", disabled_res.content[0].text)
            finally:
                await core.aclose()

        audit_lines = [json.loads(line) for line in self.audit_stream.getvalue().strip().splitlines()]
        self.assertGreaterEqual(len(audit_lines), 7)
        raw_audit = self.audit_stream.getvalue()
        self.assertNotIn(self.secret, raw_audit)
        self.assertNotIn("never-logged", raw_audit)
        tasks_record = next(r for r in audit_lines if r["path"] == "/cluster/tasks")
        self.assertEqual(tasks_record["query_keys"], ["limit", "secret_query_val"])
        self.assertEqual(tasks_record["outcome"], "ok")
        self.assertEqual(tasks_record["acl"], "proxmox-audit")
        denied_record = next(r for r in audit_lines if r["outcome"] == "denied")
        self.assertEqual(denied_record["path"], "/nodes/pve1/qemu/100/config")
        disabled_record = next(
            r for r in audit_lines if r["agent"] == "limited" and r["outcome"] == "denied"
        )
        self.assertEqual(disabled_record["denial_reason"], "Unknown or disabled agent")

    async def test_concurrency_timeout_preserves_rate_limit_and_json_numeric_secret(self) -> None:
        num_secret_file = Path(self._tmp.name) / "num_tok"
        num_secret_file.write_text("12345", encoding="utf-8")
        entered = asyncio.Event()
        release = asyncio.Event()

        class BlockingTransport(httpx2.AsyncBaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
                self.calls += 1
                if self.calls == 1:
                    entered.set()
                    await release.wait()
                return httpx2.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json={"id": 12345, "tok": "12345"},
                )

        raw = {
            "services": {
                "svc": {
                    "url": "https://svc.lan/api",
                    "rate_limit": "2/min",
                    "max_concurrent": 1,
                    "connect_timeout": "0.05s",
                    "timeout": "2s",
                    "tls": {"verify": False},
                    "auth": {"type": "bearer", "token": f"${{file:{num_secret_file}}}"},
                }
            },
            "acls": {"all": {"svc": {"GET": ["/items"]}}},
            "tokens": {"hermes": {"hash": "sha256:" + ("d" * 64), "acls": ["all"]}},
        }
        cfg = load_config_from_dict(raw)
        transport = BlockingTransport()
        core = GatewayCore(
            cfg,
            audit_logger=AuditLogger(stdout=False, redactor=cfg.redactor),
            transports={"svc": transport},
        )
        try:
            task1 = asyncio.create_task(
                core.http_request(agent_name="hermes", service="svc", method="GET", path="/items")
            )
            await entered.wait()
            timed_out = await core.http_request(
                agent_name="hermes", service="svc", method="GET", path="/items"
            )
            self.assertTrue(timed_out.is_error)
            self.assertIn("concurrency queue timed out", timed_out.content[0].text)
            release.set()
            res1 = await task1
            self.assertFalse(res1.is_error)
            body1 = json.loads(res1.content[0].text)["body"]
            self.assertEqual(body1["id"], 12345)
            self.assertEqual(body1["tok"], "[REDACTED]")

            res2 = await core.http_request(
                agent_name="hermes", service="svc", method="GET", path="/items"
            )
            self.assertFalse(res2.is_error)
        finally:
            await core.aclose()

    async def test_real_tls_ca_pinning_vs_untrusted_and_verify_false(self) -> None:
        cert_path = Path(self._tmp.name) / "server.pem"
        key_path = Path(self._tmp.name) / "server.key"
        _generate_self_signed_cert(cert_path, key_path)

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await reader.read(4096)
                body = b'{"data":{"version":"8.2"}}'
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + body
                )
                writer.write(resp)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle_client, "127.0.0.1", 0, ssl=ssl_ctx)
        port = server.sockets[0].getsockname()[1]

        try:
            def make_core(tls_cfg: dict) -> GatewayCore:
                raw = {
                    "services": {
                        "proxmox": {
                            "url": f"https://127.0.0.1:{port}/api2/json",
                            "tls": tls_cfg,
                            "auth": {
                                "type": "header",
                                "header": "Authorization",
                                "value": f"PVEAPIToken=${{env:PVE_TOKEN_ID}}=${{file:{self.secret_file}}}",
                            },
                        }
                    },
                    "acls": {"pve": {"proxmox": {"GET": ["/version"]}}},
                    "tokens": {"hermes": {"hash": "sha256:" + ("c" * 64), "acls": ["pve"]}},
                }
                with patch.dict(os.environ, {"PVE_TOKEN_ID": "audit@pve!gateway"}):
                    cfg = load_config_from_dict(raw)
                return GatewayCore(cfg, audit_logger=AuditLogger(stdout=False, redactor=cfg.redactor))

            untrusted_core = make_core({"verify": True})
            try:
                res_fail = await untrusted_core.http_request(
                    agent_name="hermes",
                    service="proxmox",
                    method="GET",
                    path="/version",
                )
                self.assertTrue(res_fail.is_error)
                self.assertEqual(res_fail.content[0].text, "Upstream TLS verification failed")
            finally:
                await untrusted_core.aclose()

            pinned_core = make_core({"verify": True, "ca": str(cert_path)})
            try:
                res_ok = await pinned_core.http_request(
                    agent_name="hermes",
                    service="proxmox",
                    method="GET",
                    path="/version",
                )
                self.assertFalse(res_ok.is_error)
                self.assertEqual(json.loads(res_ok.content[0].text)["body"]["data"]["version"], "8.2")
            finally:
                await pinned_core.aclose()

            insecure_core = make_core({"verify": False})
            try:
                res_skip = await insecure_core.http_request(
                    agent_name="hermes",
                    service="proxmox",
                    method="GET",
                    path="/version",
                )
                self.assertFalse(res_skip.is_error)
            finally:
                await insecure_core.aclose()
        finally:
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
