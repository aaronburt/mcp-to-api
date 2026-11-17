import json
import logging
import ssl
from dataclasses import dataclass
from typing import Any

import httpx2

from gateway.config import ResolvedService
from gateway.policy import PreparedBody
from gateway.secrets import Redactor


logging.getLogger("httpx2").setLevel(logging.WARNING)
logging.getLogger("httpcore2").setLevel(logging.WARNING)

_ALWAYS_BLOCKED_RESPONSE_HEADERS = frozenset({"location", "set-cookie", "www-authenticate", "proxy-authenticate"})


class UpstreamError(Exception):
    def __init__(self, error_code: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.error_code = error_code
        self.safe_message = safe_message


@dataclass(frozen=True)
class UpstreamResponse:
    status: int
    headers: dict[str, str]
    body: Any
    truncated: bool
    response_bytes: int


def build_pinned_url(service: ResolvedService, normalized_path: str) -> str:
    origin = service.origin
    if normalized_path == "/":
        expected_path = f"{origin.base_path}/" if origin.base_path else "/"
    else:
        expected_path = f"{origin.base_path}{normalized_path}"
    raw_url = f"{origin.base_url}{normalized_path}"
    parsed = httpx2.URL(raw_url)
    effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if (
        parsed.scheme.lower() != origin.scheme
        or (parsed.host or "").lower() != origin.host
        or effective_port != origin.port
        or parsed.userinfo != b""
        or parsed.query != b""
        or parsed.fragment != ""
        or parsed.path != expected_path
    ):
        raise UpstreamError("egress_pinning_failed", "Constructed URL failed egress pinning check")
    return str(parsed)


def _is_tls_exception(exc: BaseException) -> bool:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, ssl.SSLError):
            return True
        if "CERTIFICATE_VERIFY_FAILED" in str(current) or "SSL" in type(current).__name__:
            return True
        current = current.__cause__ or current.__context__
    return False


class ServiceEgressClient:
    def __init__(
        self,
        service: ResolvedService,
        redactor: Redactor,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self._service = service
        self._redactor = redactor
        timeout = httpx2.Timeout(
            timeout=service.timeout,
            connect=service.connect_timeout,
        )
        client_kwargs: dict[str, Any] = {
            "follow_redirects": False,
            "trust_env": False,
            "timeout": timeout,
        }
        if transport is not None:
            client_kwargs["transport"] = transport
        else:
            client_kwargs["verify"] = service.tls_verify
        self._client = httpx2.AsyncClient(**client_kwargs)

    async def execute(
        self,
        *,
        method: str,
        normalized_path: str,
        query_pairs: list[tuple[str, str]],
        body: PreparedBody,
    ) -> UpstreamResponse:
        target_url = build_pinned_url(self._service, normalized_path)
        headers: dict[str, str] = {}
        if body.content_type is not None:
            headers["Content-Type"] = body.content_type

        params = list(query_pairs)
        auth = self._service.auth
        if auth.style in ("header", "bearer", "basic"):
            assert auth.header_name is not None and auth.header_value is not None
            headers[auth.header_name] = auth.header_value
        elif auth.style == "query":
            assert auth.query_param is not None and auth.query_value is not None
            params.append((auth.query_param, auth.query_value))

        try:
            async with self._client.stream(
                method,
                target_url,
                params=params or None,
                headers=headers or None,
                content=body.content,
            ) as response:
                chunks: list[bytes] = []
                total = 0
                truncated = False
                max_bytes = self._service.max_response_bytes
                async for chunk in response.aiter_bytes(chunk_size=16384):
                    if not chunk:
                        continue
                    remaining = max_bytes - total
                    if len(chunk) > remaining:
                        if remaining > 0:
                            chunks.append(chunk[:remaining])
                            total += remaining
                        truncated = True
                        break
                    chunks.append(chunk)
                    total += len(chunk)

                raw_bytes = b"".join(chunks)
                allowed_headers: dict[str, str] = {}
                for h_name, h_val in response.headers.items():
                    lowered = h_name.lower()
                    if (
                        lowered in self._service.allowed_response_headers
                        and lowered not in _ALWAYS_BLOCKED_RESPONSE_HEADERS
                    ):
                        allowed_headers[lowered] = self._redactor.scrub_text(h_val)

                raw_text = raw_bytes.decode("utf-8", errors="replace")
                if not truncated and raw_text:
                    try:
                        parsed_json = json.loads(raw_text)
                    except json.JSONDecodeError:
                        parsed_body: Any = self._redactor.scrub_text(raw_text)
                    else:
                        parsed_body = self._redactor.scrub_value(parsed_json)
                else:
                    parsed_body = self._redactor.scrub_text(raw_text)

                return UpstreamResponse(
                    status=response.status_code,
                    headers=allowed_headers,
                    body=parsed_body,
                    truncated=truncated,
                    response_bytes=len(raw_bytes),
                )
        except UpstreamError:
            raise
        except httpx2.ConnectTimeout as exc:
            raise UpstreamError("upstream_connect_timeout", "Upstream connection timed out") from exc
        except httpx2.TimeoutException as exc:
            raise UpstreamError("upstream_timeout", "Upstream request timed out") from exc
        except httpx2.ConnectError as exc:
            if _is_tls_exception(exc):
                raise UpstreamError("upstream_tls_error", "Upstream TLS verification failed") from exc
            raise UpstreamError("upstream_connect_error", "Upstream connection failed") from exc
        except httpx2.HTTPError as exc:
            raise UpstreamError("upstream_http_error", "Upstream HTTP transport error") from exc

    async def aclose(self) -> None:
        await self._client.aclose()
