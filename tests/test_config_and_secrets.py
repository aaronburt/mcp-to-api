import base64
import os
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from gateway.config import ConfigError, load_config, load_config_from_dict, parse_duration
from gateway.secrets import REDACTED_MARKER, Redactor


def _make_base_config(secret_file: Path) -> dict:
    return {
        "defaults": {
            "rate_limit": "60/min",
            "max_concurrent": 4,
            "connect_timeout": "2s",
            "timeout": "10s",
            "max_response": "1MB",
            "max_request_body": "32KB",
        },
        "services": {
            "upstream": {
                "url": "https://api.lan:8443/v1",
                "description": "Internal API read-only",
                "tls": {"verify": False},
                "auth": {
                    "type": "header",
                    "header": "Authorization",
                    "value": f"Token ${{env:API_KEY_ID}}:${{file:{secret_file}}}",
                },
            }
        },
        "acls": {
            "api-readonly": {
                "upstream": {
                    "GET": ["/status", "/projects", "/projects/*/status"],
                }
            }
        },
        "tokens": {
            "agent-1": {
                "hash": "sha256:" + ("a" * 64),
                "acls": ["api-readonly"],
            }
        },
    }


class TestConfigAndSecrets(unittest.TestCase):
    def test_load_config_and_strip_trailing_newline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            secret_file = tmp_path / "api_token"
            secret_file.write_text("uuid-secret-9999\r\n", encoding="utf-8")

            raw = _make_base_config(secret_file)
            with patch.dict(os.environ, {"API_KEY_ID": "svc-account"}):
                cfg = load_config_from_dict(raw)

            svc = cfg.services["upstream"]
            self.assertEqual(
                svc.auth.header_value,
                "Token svc-account:uuid-secret-9999",
            )
            self.assertEqual(svc.origin.base_path, "/v1")
            self.assertEqual(svc.origin.port, 8443)
            self.assertEqual(svc.connect_timeout, 2.0)
            self.assertEqual(svc.timeout, 10.0)
            self.assertEqual(svc.max_response_bytes, 1024 * 1024)
            self.assertEqual(svc.max_request_body_bytes, 32 * 1024)

            scrubbed_task = cfg.redactor.scrub_text(
                '{"user":"svc-account","leak":"uuid-secret-9999"}'
            )
            self.assertIn("svc-account", scrubbed_task)
            self.assertNotIn("uuid-secret-9999", scrubbed_task)
            self.assertIn(REDACTED_MARKER, scrubbed_task)

    def test_example_yaml_validates_with_secrets(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        example_file = repo_root / "gateway.example.yaml"
        with patch.dict(
            os.environ,
            {
                "API_URL": "https://api.internal.example/api",
                "API_TOKEN": "secret-uuid-1234",
            },
        ):
            cfg = load_config(example_file)
        self.assertIn("internal-api", cfg.services)
        self.assertEqual(cfg.services["internal-api"].origin.base_url, "https://api.internal.example/api")
        self.assertIn("assistant", cfg.agents)
        self.assertIn("ci-agent", cfg.agents)
        scrubbed = cfg.redactor.scrub_text('{"user":"svc-account","tok":"secret-uuid-1234"}')
        self.assertIn("svc-account", scrubbed)
        self.assertNotIn("secret-uuid-1234", scrubbed)
        with patch.dict(
            os.environ,
            {
                "API_TOKEN": "secret-uuid-1234",
            },
            clear=True,
        ):
            with self.assertRaises(ConfigError):
                load_config(example_file)

    def test_rejects_unresolved_or_empty_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            secret_file = tmp_path / "api_token"
            secret_file.write_text("\n", encoding="utf-8")
            raw = _make_base_config(secret_file)
            with patch.dict(os.environ, {"API_KEY_ID": "svc-account"}):
                with self.assertRaises(ConfigError):
                    load_config_from_dict(raw)

            secret_file.write_text("line1\nline2", encoding="utf-8")
            with patch.dict(os.environ, {"API_KEY_ID": "svc-account"}):
                with self.assertRaises(ConfigError):
                    load_config_from_dict(raw)

            secret_file.write_text("valid-secret", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(ConfigError):
                    load_config_from_dict(raw)

    def test_rejects_bad_acls_tokens_and_urls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret_file = Path(tmp) / "api_token"
            secret_file.write_text("valid-secret", encoding="utf-8")

            with patch.dict(os.environ, {"API_KEY_ID": "svc-account"}):
                bad_acl_svc = _make_base_config(secret_file)
                bad_acl_svc["acls"]["api-readonly"]["unknown"] = {"GET": ["/x"]}
                with self.assertRaises(ConfigError):
                    load_config_from_dict(bad_acl_svc)

                bad_token_acl = _make_base_config(secret_file)
                bad_token_acl["tokens"]["agent-1"]["acls"] = ["missing-acl"]
                with self.assertRaises(ConfigError):
                    load_config_from_dict(bad_token_acl)

                bad_pattern = _make_base_config(secret_file)
                bad_pattern["acls"]["api-readonly"]["upstream"]["GET"] = ["/projects/*/stat*"]
                with self.assertRaises(ConfigError):
                    load_config_from_dict(bad_pattern)

                bad_http = _make_base_config(secret_file)
                bad_http["services"]["upstream"]["url"] = "http://api.lan:8443/v1"
                with self.assertRaises(ConfigError):
                    load_config_from_dict(bad_http)

                bad_tls = _make_base_config(secret_file)
                bad_tls["services"]["upstream"]["tls"] = {"verify": True, "ca": "/etc/ssl/ca.pem"}
                with self.assertRaises(ConfigError):
                    load_config_from_dict(bad_tls)

                bad_non_ascii_acl = _make_base_config(secret_file)
                bad_non_ascii_acl["acls"]["api-readonly"]["upstream"]["GET"] = ["/projects/\u00e9"]
                with self.assertRaises(ConfigError):
                    load_config_from_dict(bad_non_ascii_acl)

                dup_hash = _make_base_config(secret_file)
                dup_hash["tokens"]["other"] = {
                    "hash": dup_hash["tokens"]["agent-1"]["hash"],
                    "acls": ["api-readonly"],
                }
                with self.assertRaises(ConfigError):
                    load_config_from_dict(dup_hash)

                for bad_dur in (float("nan"), float("inf"), float("-inf")):
                    with self.assertRaises(ConfigError):
                        parse_duration(bad_dur)

    def test_auth_styles_and_redactor_variants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            tok_file = tmp_path / "tok"
            tok_file.write_text("my+secret/token=123", encoding="utf-8")
            raw = {
                "services": {
                    "svc_bearer": {
                        "url": "https://api.example.com",
                        "auth": {"type": "bearer", "token": f"${{file:{tok_file}}}"},
                    },
                    "svc_basic": {
                        "url": "https://basic.example.com",
                        "auth": {
                            "type": "basic",
                            "username": "svcuser",
                            "password": f"${{file:{tok_file}}}",
                        },
                    },
                    "svc_query": {
                        "url": "https://q.example.com",
                        "auth": {
                            "type": "query",
                            "param": "apiKey",
                            "value": f"${{file:{tok_file}}}",
                        },
                    },
                },
                "acls": {
                    "all": {
                        "svc_bearer": {"GET": ["/items"]},
                        "svc_basic": {"GET": ["/items"]},
                        "svc_query": {"GET": ["/items"]},
                    }
                },
                "tokens": {
                    "agent": {"hash": "sha256:" + ("b" * 64), "acls": ["all"]}
                },
            }
            cfg = load_config_from_dict(raw)
            self.assertEqual(cfg.services["svc_query"].reserved_query_params, frozenset({"apikey"}))
            basic_b64 = base64.b64encode(b"svcuser:my+secret/token=123").decode("ascii")
            self.assertEqual(cfg.services["svc_basic"].auth.header_value, f"Basic {basic_b64}")

            secret = "my+secret/token=123"
            samples = [
                secret,
                urllib.parse.quote(secret, safe=""),
                urllib.parse.quote_plus(secret),
                base64.b64encode(secret.encode()).decode(),
                base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
                basic_b64,
            ]
            for sample in samples:
                self.assertEqual(cfg.redactor.scrub_text(f"err={sample}"), "err=[REDACTED]")
            self.assertEqual(cfg.redactor.scrub_text("user=svcuser"), "user=svcuser")

            r = Redactor(["abc/def"])
            scrubbed = r.scrub_value({"nested": ["abc/def", {"k": "abc/def"}]})
            self.assertEqual(scrubbed, {"nested": ["[REDACTED]", {"k": "[REDACTED]"}]})

            short_r = Redactor(["a"])
            self.assertEqual(short_r.scrub_text("MYQ bcd"), "MYQ bcd")


if __name__ == "__main__":
    unittest.main()
