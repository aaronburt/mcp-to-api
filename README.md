# MCP Credential Gateway

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![MCP Streamable HTTP](https://img.shields.io/badge/MCP-Streamable%20HTTP-6E56CF)](https://modelcontextprotocol.io/)
[![Docker Hardened](https://img.shields.io/badge/docker-non--root%20%7C%20read--only-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![Security Least-Privilege](https://img.shields.io/badge/security-least--privilege-2EA44F)](#security-features)
[![Tests](https://img.shields.io/badge/tests-unittest-success)](#running-tests)

A least-privilege **Model Context Protocol (MCP)** credential gateway that isolates upstream API secrets from AI agents. Agents authenticate with per-agent bearer tokens and invoke generic MCP tools (`list_services`, `http_request`), while upstream credentials, TLS pinning, route allowlists, and rate limits remain strictly enforced inside the gateway.

---

## Security Features

- **Zero Credential Exposure:** Upstream secrets stay in environment variables or mounted secret files (`${env:...}`, `${secret_env:...}`, `${file:...}`) and are never returned to MCP clients.
- **Automatic Secret Redaction:** Scrubs upstream response bodies, allowed headers, and audit denial messages against raw, URL-encoded, Base64 / URL-safe Base64, and JSON-escaped variants of configured secrets.
- **Strict Method & Path Allowlisting:** Denies any HTTP method or path not explicitly granted in an agent's ACLs. Paths are restricted to safe ASCII RFC 3986 path characters (rejecting percent-encodings, traversal segments, queries, fragments, and non-ASCII characters).
- **Egress Pinning & Hardening:** Pins every upstream request to its configured scheme, host, port, and base path; disables HTTP redirects (`follow_redirects=False`) and ambient proxy env vars (`trust_env=False`); blocks `Set-Cookie`, `Location`, `WWW-Authenticate`, and `Proxy-Authenticate` response headers; and caps response/request body sizes.
- **Per-Agent Isolation & Session Binding:** Constant-time `sha256` token verification, per-token MCP instructions/resource scoping, and MCP session binding to prevent cross-agent session hijacking.
- **Traffic & Abuse Controls:** Sliding-window per-agent and global rate limits, per-service concurrency semaphores, Host/Origin header validation, and structured JSONL audit logging with sanitized fields.
- **Hardened Container Runtime:** Runs as non-root UID/GID `10001` with a read-only root filesystem, `CAP_DROP=ALL`, `no-new-privileges:true`, and localhost port binding (`127.0.0.1:8080`) by default.

---

## MCP Surface

| Primitive | Name / URI | Description |
| :--- | :--- | :--- |
| **Tool** | `list_services` | Returns only the services, allowed HTTP methods, path patterns, rate limits, and response byte caps granted to the authenticated agent. |
| **Tool** | `http_request` | Executes an allowlisted upstream request (`service`, `method`, `path`, optional `query`, `body`, `body_format` as `json` or `form`) and returns `{status, headers, body, truncated}`. |
| **Resource** | `gateway://instructions.md` | Dynamically renders Markdown instructions and granted routes for the authenticated agent (also injected into MCP initialization instructions). |
| **HTTP** | `GET /healthz` | Unauthenticated liveness probe returning `{"status":"ok","config_loaded":true,"secrets_present":true}`. |

---

## Quickstart: Proxmox VE Audit Setup

### 1. Create a read-only Proxmox API token

On a Proxmox VE node:

```bash
pveum user add audit@pve --comment "Read-only MCP audit account"
pveum user token add audit@pve gateway --privsep 1
pveum acl modify / --tokens audit@pve!gateway --role PVEAuditor
```

Set the upstream connection values in `.env` (or your process environment):

```env
PVE_URL=https://pve.lan:8006/api2/json
PVE_TOKEN_ID=audit@pve!gateway
PVE_TOKEN_SECRET=<generated-uuid-secret>
```

### 2. Configure `gateway.yaml` and TLS

Copy `gateway.proxmox.example.yaml` to `gateway.yaml`. `gateway.proxmox.example.yaml` uses `tls: { verify: false }` for Proxmox's default self-signed certificate. To pin the Proxmox root CA, mount `/etc/pve/pve-root-ca.pem` into `/etc/gateway/pve-root-ca.pem` and configure:

```yaml
tls:
  verify: true
  ca: /etc/gateway/pve-root-ca.pem
```

### 3. Generate per-agent bearer tokens

```bash
python -m gateway.cli token --name hermes --acls proxmox-audit
python -m gateway.cli token --name claude-code --acls proxmox-audit
```

Copy the printed `sha256:...` hashes under `tokens:` in `gateway.yaml`, and configure each MCP client with its corresponding raw `token:` value.

### 4. Validate and run

Validate configuration before starting:

```bash
python -m gateway.cli --config gateway.yaml --check
```

Run with Docker Compose (binds `127.0.0.1:8080` by default; set `GATEWAY_BIND_IP=0.0.0.0` in `.env` if LAN access is required):

```bash
docker compose up -d --build
```

Verify health:

```bash
curl http://127.0.0.1:8080/healthz
```

For running locally without Docker (after `pip install -e .`):

```bash
mcp-gateway --config gateway.yaml
```

### 5. Connect an MCP client

Point your MCP client at the Streamable HTTP endpoint with its Bearer token:

- **URL:** `http://127.0.0.1:8080/mcp`
- **Header:** `Authorization: Bearer <agent-token>`

---

## Configuration Reference

- **Secret placeholders:**
  - `${env:VAR}`: Reads an environment variable (also redacted automatically when used inside `bearer.token`, `basic.password`, or `header`/`query` without explicit secret placeholders).
  - `${secret_env:VAR}`: Marks an environment variable as a secret to scrub from responses and audit logs.
  - `${file:/path/to/secret}`: Reads a secret from a file, strips trailing `\r`/`\n`, and registers it for redaction.
- **`defaults`:** `rate_limit` (`60/min`), `global_rate_limit` (`null`), `max_concurrent` (`10`), `connect_timeout` (`5s`), `timeout` (`20s`), `max_response` (`2MB`), `max_request_body` (`64KB`), `allowed_response_headers` (`[content-type, etag, last-modified, retry-after]`).
- **`services.<name>.auth.type`:** Supports `header`, `bearer`, `basic`, and `query` (automatically reserves `query.param` so agents cannot override auth parameters via `query`).
- **`acls.<acl>.<service>.<METHOD>`:** List of relative path patterns starting with `/`. Exact segment wildcards (`*`, such as `/nodes/*/status`) are supported.
- **`tokens.<agent>`:** Requires `hash: sha256:<64-hex>`, non-empty `acls`, and optional `enabled: true|false`. Duplicate token hashes across agents are rejected.
- **`server`:** Configures `host`, `port`, `mcp_path` (`/mcp`), `allowed_hosts`, `allowed_origins`, `block_browser_origins` (`true`), `stateless_http` (`false`), and `invalid_request_rate_limit` (`120/min`).
- **`audit`:** Configures JSONL audit logging to `stdout` (`true`) and/or `file` (`null`).

---

## Running Tests

On Linux/macOS:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

On Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"; python -m unittest discover -s tests -v
```
