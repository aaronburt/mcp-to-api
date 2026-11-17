import json
import urllib.parse
from dataclasses import dataclass
from typing import Any

from gateway.config import (
    ALLOWED_HTTP_METHODS,
    AgentTokenSpec,
    CompiledACLRule,
    LoadedGatewayConfig,
)


class PolicyDenial(Exception):
    def __init__(self, reason_code: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.reason_code = reason_code
        self.safe_message = safe_message


@dataclass(frozen=True)
class PreparedBody:
    content: bytes | None
    content_type: str | None


ALLOWED_PATH_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:@!$&'()*+,=/"
)


def validate_and_normalize_path(raw_path: Any) -> tuple[str, tuple[str, ...]]:
    if not isinstance(raw_path, str) or not raw_path:
        raise PolicyDenial("invalid_path", "Path must be a non-empty string starting with '/'")
    if "://" in raw_path:
        raise PolicyDenial("invalid_path", "Absolute URLs are not allowed in path")
    if not raw_path.startswith("/"):
        raise PolicyDenial("invalid_path", "Path must be relative to the service and start with '/'")
    if raw_path.startswith("//"):
        raise PolicyDenial("invalid_path", "Protocol-relative or empty path segments are not allowed")

    for ch in raw_path:
        if ch not in ALLOWED_PATH_CHARS:
            raise PolicyDenial("invalid_path", "Path contains forbidden or non-ASCII characters")

    if raw_path == "/":
        return "/", ()

    if raw_path.endswith("/"):
        raise PolicyDenial("invalid_path", "Path cannot contain empty trailing segments")

    segments = tuple(raw_path[1:].split("/"))
    for seg in segments:
        if not seg or seg in (".", ".."):
            raise PolicyDenial("invalid_path", "Path cannot contain empty, '.', or '..' segments")
    return raw_path, segments


def validate_method(raw_method: Any) -> str:
    if not isinstance(raw_method, str) or not raw_method:
        raise PolicyDenial("invalid_method", "HTTP method must be a non-empty string")
    if any(ch.isspace() for ch in raw_method):
        raise PolicyDenial("invalid_method", "HTTP method cannot contain whitespace")
    method = raw_method.upper()
    if method not in ALLOWED_HTTP_METHODS:
        raise PolicyDenial("invalid_method", f"Unsupported HTTP method '{raw_method}'")
    return method


def collect_agent_service_rules(
    config: LoadedGatewayConfig,
    agent: AgentTokenSpec,
    service_name: str,
) -> dict[str, list[CompiledACLRule]]:
    if not isinstance(service_name, str) or not service_name:
        raise PolicyDenial("invalid_service", "Service name must be a non-empty string")
    rules_by_method: dict[str, list[CompiledACLRule]] = {}
    for acl_name in agent.acls:
        svc_map = config.acl_rules.get(acl_name, {})
        method_map = svc_map.get(service_name)
        if not method_map:
            continue
        for method, rules in method_map.items():
            rules_by_method.setdefault(method, []).extend(rules)
    if not rules_by_method:
        raise PolicyDenial(
            "service_not_granted",
            f"Service '{service_name}' is not granted to this agent; call list_services to see available services",
        )
    return rules_by_method


def match_allowlist(
    rules_by_method: dict[str, list[CompiledACLRule]],
    method: str,
    path: str,
    segments: tuple[str, ...],
    service_name: str,
) -> CompiledACLRule:
    for rule in rules_by_method.get(method, ()):
        if len(rule.segments) != len(segments):
            continue
        if all(r_seg == "*" or r_seg == p_seg for r_seg, p_seg in zip(rule.segments, segments)):
            return rule
    raise PolicyDenial(
        "path_not_allowed",
        f"{method} {path} is not allowed for {service_name}; call list_services to see allowed paths",
    )


def _scalar_to_str(value: Any, context: str) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        for ch in value:
            code = ord(ch)
            if code < 0x20 and ch != "\t":
                raise PolicyDenial("invalid_query", f"{context} contains control characters")
            if code == 0x7F:
                raise PolicyDenial("invalid_query", f"{context} contains control characters")
        return value
    raise PolicyDenial("invalid_query", f"{context} must be a scalar value")


def validate_query(
    query: Any,
    reserved_keys: frozenset[str],
) -> tuple[list[tuple[str, str]], list[str]]:
    if query is None:
        return [], []
    if not isinstance(query, dict):
        raise PolicyDenial("invalid_query", "Query parameters must be an object mapping keys to values")

    pairs: list[tuple[str, str]] = []
    keys: list[str] = []
    for key, val in query.items():
        if not isinstance(key, str) or not key:
            raise PolicyDenial("invalid_query", "Query parameter names must be non-empty strings")
        for ch in key:
            code = ord(ch)
            if code < 0x21 or code == 0x7F or ch in ("=", "&", "#", "?"):
                raise PolicyDenial("invalid_query", f"Invalid query parameter name '{key}'")
        if key.lower() in reserved_keys:
            raise PolicyDenial(
                "reserved_query_param",
                f"Query parameter '{key}' is reserved for authentication",
            )
        keys.append(key)
        if isinstance(val, list):
            for item in val:
                pairs.append((key, _scalar_to_str(item, f"Query parameter '{key}'")))
        else:
            pairs.append((key, _scalar_to_str(val, f"Query parameter '{key}'")))
    return pairs, keys


def _reject_json_constant(val: str) -> Any:
    raise ValueError(f"Invalid JSON constant: {val}")


def validate_body(
    method: str,
    body: Any,
    body_format: Any,
    max_body_bytes: int,
) -> PreparedBody:
    fmt = "json" if body_format is None else body_format
    if fmt not in ("json", "form"):
        raise PolicyDenial("invalid_body", "body_format must be 'json' or 'form'")
    if body is None:
        return PreparedBody(content=None, content_type=None)
    if method in ("GET", "HEAD"):
        raise PolicyDenial("body_not_allowed", f"{method} requests cannot carry a body")

    if fmt == "json":
        if isinstance(body, str):
            try:
                json.loads(body, parse_constant=_reject_json_constant)
            except (json.JSONDecodeError, ValueError) as exc:
                raise PolicyDenial("invalid_body", "String body is not valid JSON") from exc
            encoded = body.encode("utf-8")
        elif isinstance(body, (dict, list, int, float, bool)):
            try:
                encoded = json.dumps(
                    body,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            except ValueError as exc:
                raise PolicyDenial("invalid_body", "JSON body cannot contain NaN or Infinity") from exc
        else:
            raise PolicyDenial("invalid_body", "JSON body must be an object, array, scalar, or JSON string")
        content_type = "application/json"
    else:
        if isinstance(body, dict):
            form_pairs: list[tuple[str, str]] = []
            for key, val in body.items():
                if not isinstance(key, str) or not key:
                    raise PolicyDenial("invalid_body", "Form field names must be non-empty strings")
                if isinstance(val, list):
                    for item in val:
                        form_pairs.append((key, _scalar_to_str(item, f"Form field '{key}'")))
                else:
                    form_pairs.append((key, _scalar_to_str(val, f"Form field '{key}'")))
            encoded = urllib.parse.urlencode(form_pairs).encode("utf-8")
        elif isinstance(body, str):
            if any(ord(c) < 0x20 or ord(c) == 0x7F for c in body):
                raise PolicyDenial("invalid_body", "Form body string contains control characters")
            encoded = body.encode("utf-8")
        else:
            raise PolicyDenial("invalid_body", "Form body must be an object or form-encoded string")
        content_type = "application/x-www-form-urlencoded"

    if len(encoded) > max_body_bytes:
        raise PolicyDenial(
            "body_too_large",
            f"Request body exceeds maximum size of {max_body_bytes} bytes",
        )
    return PreparedBody(content=encoded, content_type=content_type)
