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
                "upstream": {
                    "url": "https://api.lan:8443/v1",
                    "tls": {"verify": False},
                    "auth": {
                        "type": "header",
                        "header": "Authorization",
                        "value": f"Token ${{env:API_KEY_ID}}:${{file:{secret_file}}}",
                    },
                },
                "other": {
                    "url": "https://other.lan/v1",
                    "tls": {"verify": False},
                    "auth": {"type": "query", "param": "api_key", "value": f"${{file:{secret_file}}}"},
                },
            },
            "acls": {
                "api-read": {
                    "upstream": {
                        "GET": ["/status", "/projects", "/projects/*/status", "/projects/*/items"],
                    }
                },
                "api-extra": {
                    "upstream": {
                        "GET": ["/users"],
                    }
                },
            },
            "tokens": {
                "agent-1": {
                    "hash": "sha256:" + ("1" * 64),
                    "acls": ["api-read", "api-extra"],
                }
            },
        }
        with patch.dict(os.environ, {"API_KEY_ID": "svc-account"}):
            self.cfg = load_config_from_dict(raw)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_path_hygiene_rejections(self) -> None:
        bad_paths = [
            "",
            "projects",
            "https://evil.com/projects",
            "//evil.com/projects",
            "/projects/",
            "/projects//status",
            "/projects/./status",
            "/projects/../admin/keys",
            "/projects\\status",
            "/projects?foo=1",
            "/projects#frag",
            "/projects;jsessionid=1",
            "/projects/item%2e%2e",
            "/projects/%2E%2E/status",
            "/projects/item%2fstatus",
            "/projects/item%2Fstatus",
            "/projects/item%5cstatus",
            "/projects/item%252e",
            "/projects/item%00",
            "/projects/item%3f",
            "/projects/item%23",
            "/projects/item%3b",
            "/projects/item%zz",
            "/projects/item%",
            "/projects/item\n",
            "/projects/item status",
            "/projects/item%3a1",
            "/projects/item\u00e91",
        ]
        for bad in bad_paths:
            with self.subTest(bad=bad):
                with self.assertRaises(PolicyDenial):
                    validate_and_normalize_path(bad)

        norm, segs = validate_and_normalize_path("/projects/proj1/status")
        self.assertEqual(norm, "/projects/proj1/status")
        self.assertEqual(segs, ("projects", "proj1", "status"))

        rfc_norm, rfc_segs = validate_and_normalize_path("/projects/ID:proj1:001@org!tok")
        self.assertEqual(rfc_norm, "/projects/ID:proj1:001@org!tok")
        self.assertEqual(rfc_segs, ("projects", "ID:proj1:001@org!tok"))

    def test_allowlist_and_union_of_acls(self) -> None:
        agent = self.cfg.agents["agent-1"]
        rules = collect_agent_service_rules(self.cfg, agent, "upstream")

        p, s = validate_and_normalize_path("/projects/proj1/status")
        matched = match_allowlist(rules, "GET", p, s, "upstream")
        self.assertEqual(matched.acl_name, "api-read")

        p2, s2 = validate_and_normalize_path("/users")
        matched2 = match_allowlist(rules, "GET", p2, s2, "upstream")
        self.assertEqual(matched2.acl_name, "api-extra")

        for denied_path in ("/projects/proj1", "/projects/proj1/items/100/config", "/admin/keys"):
            dp, ds = validate_and_normalize_path(denied_path)
            with self.assertRaises(PolicyDenial):
                match_allowlist(rules, "GET", dp, ds, "upstream")

        with self.assertRaises(PolicyDenial):
            match_allowlist(rules, validate_method("POST"), p, s, "upstream")

        with self.assertRaises(PolicyDenial):
            collect_agent_service_rules(self.cfg, agent, "other")

    def test_query_and_body_validation(self) -> None:
        reserved = self.cfg.services["other"].reserved_query_params
        for key in ("api_key", "API_KEY", "Api_Key"):
            with self.assertRaises(PolicyDenial):
                validate_query({key: "override"}, reserved)

        pairs, keys = validate_query({"type": "service", "active": True, "limit": 10}, reserved)
        self.assertEqual(pairs, [("type", "service"), ("active", "true"), ("limit", "10")])
        self.assertEqual(keys, ["type", "active", "limit"])

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

        prepared_json = validate_body("POST", {"name": "item1"}, "json", 1024)
        self.assertEqual(prepared_json.content_type, "application/json")
        self.assertEqual(prepared_json.content, b'{"name":"item1"}')

        prepared_form = validate_body("POST", {"project": "proj1", "id": 100}, "form", 1024)
        self.assertEqual(prepared_form.content_type, "application/x-www-form-urlencoded")
        self.assertEqual(prepared_form.content, b"project=proj1&id=100")

    async def test_sliding_window_and_concurrency(self) -> None:
        clock = FakeClock()
        limiter = SlidingWindowLimiter(clock=clock)
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

        cm = ConcurrencyManager({"upstream": 1})
        async with cm.slot("upstream", wait_timeout=0.5):
            with self.assertRaises(ConcurrencyLimitTimeout):
                async with cm.slot("upstream", wait_timeout=0.02):
                    pass


if __name__ == "__main__":
    unittest.main()
