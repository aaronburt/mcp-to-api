import json
import time
import uuid
from typing import Any

import httpx2
from mcp.types import CallToolResult, TextContent

from gateway.audit import AuditLogger, safe_audit_str
from gateway.config import AgentTokenSpec, LoadedGatewayConfig
from gateway.egress import ServiceEgressClient, UpstreamError
from gateway.policy import (
    PolicyDenial,
    collect_agent_service_rules,
    match_allowlist,
    validate_and_normalize_path,
    validate_body,
    validate_method,
    validate_query,
)
from gateway.ratelimit import (
    ConcurrencyLimitTimeout,
    ConcurrencyManager,
    RateLimitExceeded,
    SlidingWindowLimiter,
)


_safe_audit_str = safe_audit_str


class GatewayCore:
    def __init__(
        self,
        config: LoadedGatewayConfig,
        *,
        audit_logger: AuditLogger | None = None,
        rate_limiter: SlidingWindowLimiter | None = None,
        invalid_limiter: SlidingWindowLimiter | None = None,
        transports: dict[str, httpx2.AsyncBaseTransport] | None = None,
    ) -> None:
        self.config = config
        self.audit = audit_logger or AuditLogger(
            stdout=config.audit_stdout,
            file_path=config.audit_file,
            redactor=config.redactor,
        )
        self.rate_limiter = rate_limiter or SlidingWindowLimiter()
        self.invalid_limiter = invalid_limiter or SlidingWindowLimiter()
        self.concurrency = ConcurrencyManager(
            {name: svc.max_concurrent for name, svc in config.services.items()}
        )
        override_transports = transports or {}
        self.egress_clients = {
            name: ServiceEgressClient(
                svc,
                config.redactor,
                transport=override_transports.get(name),
            )
            for name, svc in config.services.items()
        }

    def get_agent(self, agent_name: str) -> AgentTokenSpec | None:
        agent = self.config.agents.get(agent_name)
        if agent is None or not agent.enabled:
            return None
        return agent

    def _allowed_services_for_agent(self, agent: AgentTokenSpec) -> list[dict[str, Any]]:
        services_list: list[dict[str, Any]] = []
        for svc_name, svc in self.config.services.items():
            allowed_by_method: dict[str, list[str]] = {}
            seen_by_method: dict[str, set[str]] = {}
            for acl_name in agent.acls:
                method_map = self.config.acl_rules.get(acl_name, {}).get(svc_name, {})
                for method, rules in method_map.items():
                    bucket = allowed_by_method.setdefault(method, [])
                    seen = seen_by_method.setdefault(method, set())
                    for rule in rules:
                        if rule.pattern not in seen:
                            seen.add(rule.pattern)
                            bucket.append(rule.pattern)
            if not allowed_by_method:
                continue
            entry: dict[str, Any] = {
                "name": svc.name,
                "description": svc.description,
                "rate_limit": svc.rate_limit.raw,
                "max_response_bytes": svc.max_response_bytes,
                "allowed": allowed_by_method,
            }
            if svc.notes:
                entry["notes"] = svc.notes
            services_list.append(entry)
        return services_list

    def render_instructions(self, agent_name: str) -> str:
        base_lines = [
            "# MCP Credential Gateway Instructions",
            "",
            (
                "Call `http_request` with a granted `service`, uppercase `method`, and relative `path` "
                "(do not pass full URLs, `..`, or query strings inside `path`). "
                "Call `list_services` anytime for structured limits and schema details."
            ),
        ]
        agent = self.get_agent(agent_name)
        if agent is None:
            return "\n".join(base_lines)

        services_list = self._allowed_services_for_agent(agent)
        base_lines.extend(["", f"## Allowed Routes for `{agent.name}`"])
        if not services_list:
            base_lines.extend(["", "No services are currently granted to this token."])
            return "\n".join(base_lines)

        for entry in services_list:
            base_lines.extend(["", f"### `{entry['name']}`"])
            if entry["description"]:
                base_lines.append(entry["description"])
            if "notes" in entry:
                base_lines.append(f"- Notes: {entry['notes']}")
            base_lines.append(
                f"- Limits: `{entry['rate_limit']}`, max response `{entry['max_response_bytes']}` bytes"
            )
            for method, patterns in entry["allowed"].items():
                for pattern in patterns:
                    base_lines.append(f"- `{method} {pattern}`")
        return "\n".join(base_lines)

    async def list_services(self, agent_name: str) -> dict[str, Any]:
        started = time.monotonic()
        request_id = uuid.uuid4().hex[:12]
        agent = self.get_agent(agent_name)
        if agent is None:
            self.audit.log(
                request_id=request_id,
                agent=agent_name,
                service=None,
                method="MCP",
                path="list_services",
                query_keys=[],
                status=None,
                response_bytes=0,
                duration_ms=(time.monotonic() - started) * 1000.0,
                outcome="denied",
                denial_reason="Unknown or disabled agent",
            )
            return {"services": []}

        services_list = self._allowed_services_for_agent(agent)

        self.audit.log(
            request_id=request_id,
            agent=agent.name,
            service=None,
            method="MCP",
            path="list_services",
            query_keys=[],
            status=200,
            response_bytes=0,
            duration_ms=(time.monotonic() - started) * 1000.0,
            outcome="ok",
        )
        return {"services": services_list}

    async def _should_audit_denial(self, agent_name: str) -> bool:
        try:
            await self.invalid_limiter.check_and_record(
                [(f"denied:{agent_name}", "denied", self.config.invalid_request_rate_limit)]
            )
            return True
        except RateLimitExceeded:
            return False

    async def http_request(
        self,
        *,
        agent_name: str,
        service: str,
        method: str,
        path: str,
        query: dict[str, Any] | None = None,
        body: Any = None,
        body_format: str | None = None,
    ) -> CallToolResult:
        started = time.monotonic()
        request_id = uuid.uuid4().hex[:12]
        agent = self.get_agent(agent_name)
        if agent is None:
            if await self._should_audit_denial(agent_name):
                self.audit.log(
                    request_id=request_id,
                    agent=agent_name,
                    service=service,
                    method=method,
                    path=path,
                    query_keys=[str(k)[:128] for k in query.keys()] if isinstance(query, dict) else [],
                    status=None,
                    response_bytes=0,
                    duration_ms=(time.monotonic() - started) * 1000.0,
                    outcome="denied",
                    denial_reason="Unknown or disabled agent",
                )
            return CallToolResult(
                content=[TextContent(type="text", text="Agent identity is not authorized")],
                is_error=True,
            )

        audit_service = _safe_audit_str(service, 128)
        audit_method: str | None = _safe_audit_str(method, 16)
        audit_path: str | None = _safe_audit_str(path, 512)
        query_keys: list[str] = (
            [str(k)[:128] for k in query.keys()] if isinstance(query, dict) else []
        )
        matched_acl: str | None = None

        try:
            rules_by_method = collect_agent_service_rules(self.config, agent, service)
            svc = self.config.services[service]

            normalized_path, segments = validate_and_normalize_path(path)
            audit_path = normalized_path

            normalized_method = validate_method(method)
            audit_method = normalized_method

            matched_rule = match_allowlist(
                rules_by_method,
                normalized_method,
                normalized_path,
                segments,
                svc.name,
            )
            matched_acl = matched_rule.acl_name

            query_pairs, validated_query_keys = validate_query(query, svc.reserved_query_params)
            query_keys = validated_query_keys

            prepared_body = validate_body(
                normalized_method,
                body,
                body_format,
                svc.max_request_body_bytes,
            )

            rate_checks = [
                (f"agent:{agent.name}:{svc.name}", f"{agent.name} on {svc.name}", svc.rate_limit)
            ]
            if svc.global_rate_limit is not None:
                rate_checks.append(
                    (f"global:{svc.name}", f"global {svc.name}", svc.global_rate_limit)
                )
            await self.rate_limiter.check(rate_checks)

            client = self.egress_clients[svc.name]
            async with self.concurrency.slot(svc.name, svc.connect_timeout):
                await self.rate_limiter.check_and_record(rate_checks)
                response = await client.execute(
                    method=normalized_method,
                    normalized_path=normalized_path,
                    query_pairs=query_pairs,
                    body=prepared_body,
                )

            self.audit.log(
                request_id=request_id,
                agent=agent.name,
                service=svc.name,
                method=normalized_method,
                path=normalized_path,
                query_keys=query_keys,
                status=response.status,
                response_bytes=response.response_bytes,
                duration_ms=(time.monotonic() - started) * 1000.0,
                outcome="ok",
                acl=matched_acl,
            )

            payload = {
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
                "truncated": response.truncated,
            }
            return CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=json.dumps(payload, ensure_ascii=False),
                    )
                ],
                is_error=False,
            )

        except PolicyDenial as exc:
            if await self._should_audit_denial(agent.name):
                self.audit.log(
                    request_id=request_id,
                    agent=agent.name,
                    service=audit_service,
                    method=audit_method,
                    path=audit_path,
                    query_keys=query_keys,
                    status=None,
                    response_bytes=0,
                    duration_ms=(time.monotonic() - started) * 1000.0,
                    outcome="denied",
                    acl=matched_acl,
                    denial_reason=exc.safe_message,
                )
            return CallToolResult(
                content=[TextContent(type="text", text=exc.safe_message)],
                is_error=True,
            )

        except RateLimitExceeded as exc:
            message = f"Rate limit exceeded for {exc.scope}; retry in {exc.retry_after:.1f}s"
            if await self._should_audit_denial(agent.name):
                self.audit.log(
                    request_id=request_id,
                    agent=agent.name,
                    service=audit_service,
                    method=audit_method,
                    path=audit_path,
                    query_keys=query_keys,
                    status=429,
                    response_bytes=0,
                    duration_ms=(time.monotonic() - started) * 1000.0,
                    outcome="denied",
                    acl=matched_acl,
                    denial_reason=message,
                )
            return CallToolResult(
                content=[TextContent(type="text", text=message)],
                is_error=True,
            )

        except (ConcurrencyLimitTimeout, UpstreamError) as exc:
            message = exc.safe_message if isinstance(exc, UpstreamError) else str(exc)
            self.audit.log(
                request_id=request_id,
                agent=agent.name,
                service=audit_service,
                method=audit_method,
                path=audit_path,
                query_keys=query_keys,
                status=None,
                response_bytes=0,
                duration_ms=(time.monotonic() - started) * 1000.0,
                outcome="error",
                acl=matched_acl,
                denial_reason=message,
            )
            return CallToolResult(
                content=[TextContent(type="text", text=message)],
                is_error=True,
            )

    async def aclose(self) -> None:
        for client in self.egress_clients.values():
            await client.aclose()
        self.audit.close()
