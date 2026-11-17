from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.lowlevel.server import StreamableHTTPASGIApp
from mcp.server.mcpserver import Context
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp

from gateway.auth import GatewayAuthMiddleware, TokenAuthenticator
from gateway.gateway import GatewayCore


def create_mcp_server(core: GatewayCore) -> MCPServer:
    server = MCPServer(
        name="mcp-credential-gateway",
        version="0.1.0",
        instructions=(
            "Call list_services to discover which services, HTTP methods, and relative path "
            "patterns you are allowed to access, then call http_request with relative paths."
        ),
    )

    def resolve_agent_name() -> str:
        token = get_access_token()
        if token is None:
            raise PermissionError("Unauthenticated MCP request")
        return token.client_id

    @server.tool(
        name="list_services",
        description=(
            "List the upstream API services available to this agent, including allowed "
            "HTTP methods, path patterns, rate limits, and response caps."
        ),
    )
    async def list_services(ctx: Context) -> dict[str, Any]:
        agent_name = resolve_agent_name()
        return await core.list_services(agent_name)

    @server.tool(
        name="http_request",
        description=(
            "Execute an allowlisted HTTP request against a configured upstream service. "
            "Paths must be relative to the service base URL (e.g. '/nodes', not full URLs)."
        ),
        structured_output=False,
    )
    async def http_request(
        service: str,
        method: str,
        path: str,
        ctx: Context,
        query: Any = None,
        body: Any = None,
        body_format: str = "json",
    ) -> CallToolResult:
        agent_name = resolve_agent_name()
        return await core.http_request(
            agent_name=agent_name,
            service=service,
            method=method,
            path=path,
            query=query,
            body=body,
            body_format=body_format,
        )

    @server.resource(
        "gateway://instructions.md",
        name="instructions.md",
        title="Gateway Instructions",
        description="Dynamic instructions and allowed routes for the authenticated agent.",
        mime_type="text/markdown",
    )
    async def instructions_resource() -> str:
        agent_name = resolve_agent_name()
        return core.render_instructions(agent_name)

    lowlevel = server._lowlevel_server
    base_create_init_options = lowlevel.create_initialization_options

    def dynamic_create_init_options(
        notification_options: Any = None,
        experimental_capabilities: Any = None,
        extensions: Any = None,
    ) -> Any:
        opts = base_create_init_options(
            notification_options=notification_options,
            experimental_capabilities=experimental_capabilities,
            extensions=extensions,
        )
        token = get_access_token()
        if token is not None:
            return opts.model_copy(update={"instructions": core.render_instructions(token.client_id)})
        return opts

    lowlevel.create_initialization_options = dynamic_create_init_options

    return server


def create_http_app(core: GatewayCore) -> ASGIApp:
    mcp_server = create_mcp_server(core)
    session_manager = StreamableHTTPSessionManager(
        app=mcp_server._lowlevel_server,
        stateless=core.config.server.stateless_http,
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    mcp_asgi = StreamableHTTPASGIApp(session_manager)

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "config_loaded": True,
                "secrets_present": True,
            }
        )

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            try:
                yield
            finally:
                await core.aclose()

    starlette_app = Starlette(
        routes=[
            Route("/healthz", endpoint=healthz, methods=["GET"]),
            Route(core.config.server.mcp_path, endpoint=mcp_asgi),
        ],
        lifespan=lifespan,
    )

    authenticator = TokenAuthenticator(core.config.tokens)
    return GatewayAuthMiddleware(
        starlette_app,
        authenticator=authenticator,
        server_config=core.config.server,
        audit_logger=core.audit,
        invalid_limiter=core.invalid_limiter,
        invalid_rate_spec=core.config.invalid_request_rate_limit,
    )
