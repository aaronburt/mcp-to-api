import hashlib
import hmac
import json
import uuid
from typing import Any

from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.authentication import AuthCredentials
from starlette.types import ASGIApp, Receive, Scope, Send

from gateway.audit import AuditLogger
from gateway.config import AgentTokenSpec, RateLimitSpec, ServerConfig
from gateway.ratelimit import RateLimitExceeded, SlidingWindowLimiter


class TokenAuthenticator:
    def __init__(self, tokens: tuple[AgentTokenSpec, ...]) -> None:
        self._tokens = tokens

    def verify(self, raw_token: str) -> AgentTokenSpec | None:
        if not raw_token:
            return None
        candidate_hex = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        matched: AgentTokenSpec | None = None
        for spec in self._tokens:
            is_match = hmac.compare_digest(candidate_hex, spec.sha256_hex)
            if is_match and spec.enabled:
                matched = spec
        return matched


def _match_host_pattern(value: str, patterns: list[str]) -> bool:
    normalized = value.strip().lower()
    for raw_pattern in patterns:
        pattern = raw_pattern.strip().lower()
        if normalized == pattern:
            return True
        if pattern.endswith(":*"):
            prefix = pattern[:-2]
            if normalized == prefix:
                return True
            if normalized.startswith(prefix + ":"):
                port_str = normalized[len(prefix) + 1 :]
                if port_str.isdigit() and 1 <= int(port_str) <= 65535:
                    return True
    return False


def _extract_single_header(
    headers: list[tuple[bytes, bytes]], name: bytes
) -> tuple[str | None, bool]:
    target = name.lower()
    matches: list[str] = []
    for raw_key, raw_val in headers:
        if raw_key.lower() == target:
            matches.append(raw_val.decode("latin-1"))
    if len(matches) > 1:
        return None, True
    return (matches[0] if matches else None), False


async def _send_json_error(
    send: Send,
    *,
    status_code: int,
    body: dict[str, Any],
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(payload)).encode("ascii")),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": headers,
        }
    )
    await send({"type": "http.response.body", "body": payload})


class GatewayAuthMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        authenticator: TokenAuthenticator,
        server_config: ServerConfig,
        audit_logger: AuditLogger,
        invalid_limiter: SlidingWindowLimiter,
        invalid_rate_spec: RateLimitSpec,
    ) -> None:
        self._app = app
        self._authenticator = authenticator
        self._config = server_config
        self._audit = audit_logger
        self._invalid_limiter = invalid_limiter
        self._invalid_rate_spec = invalid_rate_spec

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path == "/healthz":
            await self._app(scope, receive, send)
            return

        headers = scope.get("headers", [])
        client = scope.get("client")
        client_ip = client[0] if client else None

        host_header, duplicate_host = _extract_single_header(headers, b"host")
        if duplicate_host:
            await _send_json_error(
                send,
                status_code=421,
                body={"error": "invalid_host", "error_description": "Invalid Host header"},
            )
            return
        if self._config.allowed_hosts:
            if not host_header or not _match_host_pattern(host_header, self._config.allowed_hosts):
                await _send_json_error(
                    send,
                    status_code=421,
                    body={"error": "invalid_host", "error_description": "Invalid Host header"},
                )
                return

        origin_header, duplicate_origin = _extract_single_header(headers, b"origin")
        if duplicate_origin:
            await _send_json_error(
                send,
                status_code=403,
                body={"error": "invalid_origin", "error_description": "Invalid Origin header"},
            )
            return
        if origin_header is not None:
            if self._config.allowed_origins:
                if not _match_host_pattern(origin_header, self._config.allowed_origins):
                    await _send_json_error(
                        send,
                        status_code=403,
                        body={"error": "invalid_origin", "error_description": "Origin not allowed"},
                    )
                    return
            elif self._config.block_browser_origins:
                await _send_json_error(
                    send,
                    status_code=403,
                    body={"error": "invalid_origin", "error_description": "Browser origins are not allowed"},
                )
                return

        auth_header, duplicate_auth = _extract_single_header(headers, b"authorization")
        raw_token = ""
        if not duplicate_auth and auth_header and auth_header[:7].lower() == "bearer ":
            raw_token = auth_header[7:].strip()

        agent = self._authenticator.verify(raw_token) if raw_token else None
        if agent is None:
            should_audit = True
            try:
                await self._invalid_limiter.check_and_record(
                    [(f"auth:{client_ip or 'unknown'}", "unauthenticated", self._invalid_rate_spec)]
                )
            except RateLimitExceeded:
                should_audit = False

            if should_audit:
                self._audit.log(
                    request_id=uuid.uuid4().hex[:12],
                    agent=None,
                    service=None,
                    method=scope.get("method"),
                    path=path,
                    query_keys=[],
                    status=401,
                    response_bytes=0,
                    duration_ms=0.0,
                    outcome="unauthenticated",
                    denial_reason="Missing or invalid bearer token",
                    client_ip=client_ip,
                )

            await _send_json_error(
                send,
                status_code=401,
                body={"error": "invalid_token", "error_description": "Authentication required"},
                extra_headers=[
                    (
                        b"www-authenticate",
                        b'Bearer error="invalid_token", error_description="Authentication required"',
                    )
                ],
            )
            return

        access_token = AccessToken(
            token="",
            client_id=agent.name,
            scopes=list(agent.acls),
        )
        auth_user = AuthenticatedUser(access_token)
        scope["user"] = auth_user
        scope["auth"] = AuthCredentials(list(agent.acls))
        ctx_token = auth_context_var.set(auth_user)
        try:
            await self._app(scope, receive, send)
        finally:
            auth_context_var.reset(ctx_token)
