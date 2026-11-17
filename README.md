# MCP Credential Gateway

A least-privilege MCP credential gateway that sits between AI agents and upstream HTTP APIs. Agents connect via MCP (`list_services`, `http_request`), while upstream API credentials remain inside the gateway and are never exposed to agents.

## Proxmox PVE Audit Setup

### 1. Create a read-only Proxmox API token

On a Proxmox VE node:

```bash
pveum user add audit@pve --comment "Read-only MCP audit account"
pveum user token add audit@pve gateway --privsep 1
pveum acl modify / --tokens audit@pve!gateway --role PVEAuditor
```

Set all three values in `.env` (or your environment):

```env
PVE_URL=https://pve.lan:8006/api2/json
PVE_TOKEN_ID=audit@pve!gateway
PVE_TOKEN_SECRET=<generated-uuid-secret>
```

### 2. TLS settings

`gateway.proxmox.example.yaml` defaults to `tls: { verify: false }` for Proxmox's self-signed certificate. To pin the Proxmox root CA later, mount `/etc/pve/pve-root-ca.pem` into the container and set `tls: { verify: true, ca: /etc/gateway/pve-root-ca.pem }`.

### 3. Generate agent tokens

Copy `gateway.proxmox.example.yaml` to `gateway.yaml` and generate per-agent tokens:

```bash
python -m gateway.cli token --name hermes --acls proxmox-audit
python -m gateway.cli token --name claude-code --acls proxmox-audit
```

Place the printed `sha256:...` hashes under `tokens:` in `gateway.yaml`, and save the raw `token:` values in each client's MCP configuration.

### 4. Validate and run

Validate configuration locally:

```bash
python -m gateway.cli --config gateway.yaml --check
```

Run with Docker Compose (non-root user, read-only rootfs, dropped capabilities):

```bash
docker compose up -d --build
```

Verify health:

```bash
curl http://127.0.0.1:8080/healthz
```

### 5. Connect an MCP client

Configure your MCP client with the Streamable HTTP endpoint and Bearer token:

- URL: `http://<gateway-host>:8080/mcp`
- Header: `Authorization: Bearer <agent-token>`

On connection (and via the `gateway://instructions.md` resource), the gateway dynamically generates instructions listing only the services and routes allowed for that client's token.

For running locally without Docker:

```bash
python -m gateway.cli --config gateway.yaml
```

## Running Tests

```bash
python -m unittest discover -s tests -v
```
