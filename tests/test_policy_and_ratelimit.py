import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.config import load_config_from_dict
from gateway.policy import (
    PolicyDenial,
    collect_agent_service_rules,
    match_allowlist,
    validate_and_normalize_path,
    validate_body,
    validate_method,
    validate_query,
)
from gateway.ratelimit import ConcurrencyLimitTimeout, ConcurrencyManager, RateLimitExceeded, SlidingWindowLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestPolicyAndRateLimit(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        secret_file = Path(self._tmp.name) / "tok"
        secret_file.write_text("secret-value-1234", encoding="utf-8")
        raw = {
            "services": {
                "proxmox": {
                    "url": "https://pve.lan:8006/api2/json",
                    "tls": {"verify": False},
                    "auth": {
                        "type": "header",
                        "header": "Authorization",
                        "value": f"PVEAPIToken=${{env:PVE_TOKEN_ID}}=${{file:{secret_file}}}",
                    },
                },
                "other": {
                    "url": "https://other.lan/v1",
                    "tls": {"verify": False},
                    "auth": {"type": "query", "param": "api_key", "value": f"${{file:{secret_file}}}"},
                },
            },
            "acls": {
                "pve-read": {
                    "proxmox": {
                        "GET": ["/version", "/nodes", "/nodes/*/status", "/nodes/*/qemu"],
                    }
                },
                "pve-extra": {
                    "proxmox": {
                        "GET": ["/pools"],
                    }
                },
            },
            "tokens": {
                "hermes": {
                    "hash": "sha256:" + ("1" * 64),
                    "acls": ["pve-read", "pve-extra"],
                }
            },
        }
        with patch.dict(os.environ, {"PVE_TOKEN_ID": "audit@pve!gateway"}):
            self.cfg = load_config_from_dict(raw)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_path_hygiene_rejections(self) -> None:
        bad_paths = [
            "",
            "nodes",
            "https://evil.com/nodes",
            "//evil.com/nodes",
            "/nodes/",
            "/nodes//status",
            "/nodes/./status",
            "/nodes/../access/ticket",
            "/nodes\\status",
            "/nodes?foo=1",
            "/nodes#frag",
            "/nodes;jsessionid=1",
            "/nodes/pve%2e%2e",
            "/nodes/%2E%2E/status",
            "/nodes/pve%2fstatus",
            "/nodes/pve%2Fstatus",
            "/nodes/pve%5cstatus",
            "/nodes/pve%252e",
            "/nodes/pve%00",
            "/nodes/pve%3f",
            "/nodes/pve%23",
            "/nodes/pve%3b",
            "/nodes/pve%zz",
            "/nodes/pve%",
            "/nodes/pve\n",
            "/nodes/pve status",
            "/nodes/pve%3a1",
            "/nodes/pv\u00e91",
        ]
        for bad in bad_paths:
            with self.subTest(bad=bad):
                with self.assertRaises(PolicyDenial):
                    validate_and_normalize_path(bad)

        norm, segs = validate_and_normalize_path("/nodes/pve1/status")
        self.assertEqual(norm, "/nodes/pve1/status")
        self.assertEqual(segs, ("nodes", "pve1", "status"))

        rfc_norm, rfc_segs = validate_and_normalize_path("/nodes/UPID:pve1:001@pam!tok")
        self.assertEqual(rfc_norm, "/nodes/UPID:pve1:001@pam!tok")
        self.assertEqual(rfc_segs, ("nodes", "UPID:pve1:001@pam!tok"))

    def test_allowlist_and_union_of_acls(self) -> None:
        agent = self.cfg.agents["hermes"]
        rules = collect_agent_service_rules(self.cfg, agent, "proxmox")

        p, s = validate_and_normalize_path("/nodes/pve1/status")
        matched = match_allowlist(rules, "GET", p, s, "proxmox")
        self.assertEqual(matched.acl_name, "pve-read")

        p2, s2 = validate_and_normalize_path("/pools")
        matched2 = match_allowlist(rules, "GET", p2, s2, "proxmox")
        self.assertEqual(matched2.acl_name, "pve-extra")

        for denied_path in ("/nodes/pve1", "/nodes/pve1/qemu/100/config", "/access/ticket"):
            dp, ds = validate_and_normalize_path(denied_path)
            with self.assertRaises(PolicyDenial):
                match_allowlist(rules, "GET", dp, ds, "proxmox")

        with self.assertRaises(PolicyDenial):
            match_allowlist(rules, validate_method("POST"), p, s, "proxmox")

        with self.assertRaises(PolicyDenial):
            collect_agent_service_rules(self.cfg, agent, "other")

    def test_query_and_body_validation(self) -> None:
        reserved = self.cfg.services["other"].reserved_query_params
        for key in ("api_key", "API_KEY", "Api_Key"):
            with self.assertRaises(PolicyDenial):
                validate_query({key: "override"}, reserved)

        pairs, keys = validate_query({"type": "vm", "running": True, "limit": 10}, reserved)
        self.assertEqual(pairs, [("type", "vm"), ("running", "true"), ("limit", "10")])
        self.assertEqual(keys, ["type", "running", "limit"])

        with self.assertRaises(PolicyDenial):
            validate_query({"bad": {"nested": 1}}, reserved)

        with self.assertRaises(PolicyDenial):
            validate_body("GET", {"a": 1}, "json", 1024)

        with self.assertRaises(PolicyDenial):
            validate_body("POST", {"a": "x" * 200}, "json", 64)

        for bad_json in ('{"x": NaN}', '{"x": Infinity}', "NaN"):
            with self.assertRaises(PolicyDenial):
                validate_body("POST", bad_json, "json", 1024)

        for bad_obj in ({"x": float("nan")}, {"x": float("inf")}):
            with self.assertRaises(PolicyDenial):
                validate_body("POST", bad_obj, "json", 1024)

        prepared_json = validate_body("POST", {"name": "vm1"}, "json", 1024)
        self.assertEqual(prepared_json.content_type, "application/json")
        self.assertEqual(prepared_json.content, b'{"name":"vm1"}')

        prepared_form = validate_body("POST", {"node": "pve1", "vmid": 100}, "form", 1024)
        self.assertEqual(prepared_form.content_type, "application/x-www-form-urlencoded")
        self.assertEqual(prepared_form.content, b"node=pve1&vmid=100")

    async def test_sliding_window_and_concurrency(self) -> None:
        clock = FakeClock()
        limiter = SlidingWindowLimiter(clock=clock)
        agent_spec = self.cfg.services["proxmox"].rate_limit
        from gateway.config import parse_rate_limit

        tight = parse_rate_limit("2/min")
        global_tight = parse_rate_limit("3/min")

        await limiter.check_and_record([("a1", "agent", tight), ("g", "global", global_tight)])
        await limiter.check_and_record([("a1", "agent", tight), ("g", "global", global_tight)])
        with self.assertRaises(RateLimitExceeded):
            await limiter.check_and_record([("a1", "agent", tight), ("g", "global", global_tight)])

        await limiter.check_and_record([("a2", "agent2", tight), ("g", "global", global_tight)])
        with self.assertRaises(RateLimitExceeded) as ctx:
            await limiter.check_and_record([("a2", "agent2", tight), ("g", "global", global_tight)])
        self.assertEqual(ctx.exception.scope, "global")

        clock.advance(61.0)
        await limiter.check_and_record([("a1", "agent", tight), ("g", "global", global_tight)])
        await limiter.check([("a2", "agent2", tight)])
        self.assertNotIn("a2", limiter._windows)

        bounded = SlidingWindowLimiter(clock=clock, max_keys=2)
        await bounded.check_and_record([("k1", "k1", tight)])
        await bounded.check_and_record([("k2", "k2", tight)])
        await bounded.check_and_record([("k3", "k3", tight)])
        self.assertEqual(len(bounded._windows), 2)
        self.assertNotIn("k1", bounded._windows)

        cm = ConcurrencyManager({"proxmox": 1})
        async with cm.slot("proxmox", wait_timeout=0.5):
            with self.assertRaises(ConcurrencyLimitTimeout):
                async with cm.slot("proxmox", wait_timeout=0.02):
                    pass


if __name__ == "__main__":
    unittest.main()
