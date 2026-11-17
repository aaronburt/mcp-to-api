import argparse
import hashlib
import os
import secrets
import sys
from pathlib import Path

import uvicorn

from gateway.config import ConfigError, load_config
from gateway.gateway import GatewayCore
from gateway.server import create_http_app


def generate_token_pair() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw, f"sha256:{digest}"


def token_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-gateway-token")
    parser.add_argument("--name", default="agent", help="Agent name for YAML snippet")
    parser.add_argument("--acls", nargs="+", default=["proxmox-audit"], help="ACLs for YAML snippet")
    args = parser.parse_args(argv)
    raw, hashed = generate_token_pair()
    acls_list = ", ".join(args.acls)
    print(f"token: {raw}")
    print("yaml:")
    print(f"  {args.name}:")
    print(f"    hash: {hashed}")
    print(f"    acls: [{acls_list}]")
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "token":
        return token_main(argv[1:])

    parser = argparse.ArgumentParser(prog="mcp-gateway")
    parser.add_argument(
        "--config",
        default=os.environ.get("GATEWAY_CONFIG", "/etc/gateway/gateway.yaml"),
        help="Path to gateway.yaml",
    )
    parser.add_argument("--host", default=None, help="Bind host override for HTTP transport")
    parser.add_argument("--port", type=int, default=None, help="Bind port override for HTTP transport")
    parser.add_argument("--check", action="store_true", help="Validate configuration and exit")
    args = parser.parse_args(argv)

    config_path = str(Path(args.config))
    try:
        if args.check:
            cfg = load_config(config_path)
            print(f"Configuration valid: {len(cfg.services)} service(s), {len(cfg.tokens)} token(s)")
            return 0

        cfg = load_config(config_path)
        core = GatewayCore(cfg)
        try:
            app = create_http_app(core)
            host = args.host if args.host is not None else cfg.server.host
            port = args.port if args.port is not None else cfg.server.port
            uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)
        finally:
            core.audit.close()
        return 0
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
