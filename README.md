# MCP Credential Gateway

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![MCP Streamable HTTP](https://img.shields.io/badge/MCP-Streamable%20HTTP-6E56CF)](https://modelcontextprotocol.io/)
[![Docker](https://img.shields.io/badge/docker-non--root%20%7C%20read--only-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![Tests](https://img.shields.io/badge/tests-unittest-success)](#running-tests)

A least-privilege Model Context Protocol (MCP) gateway that keeps upstream API credentials isolated from AI agents. Agents authenticate with per-agent bearer tokens and call `list_services` and `http_request` against strictly allowlisted routes, while the gateway handles credential injection, secret redaction, rate limits, and audit logging.

## Quickstart

1. Copy [gateway.example.yaml](gateway.example.yaml) to `gateway.yaml` and set your upstream credentials in `.env`:

```env
API_URL=https://api.internal.example/api
API_TOKEN=<upstream-api-secret>
```

2. Generate per-agent bearer tokens and place the printed `sha256:...` hashes under `tokens:` in `gateway.yaml`:

```bash
python -m gateway.cli token --name assistant --acls api-readonly
```

3. Validate and run (binds `127.0.0.1:8080` by default; set `GATEWAY_BIND_IP=0.0.0.0` in `.env` if needed):

```bash
python -m gateway.cli --config gateway.yaml --check
docker compose up -d
curl http://127.0.0.1:8080/healthz
```

4. Connect your MCP client to `http://127.0.0.1:8080/mcp` with `Authorization: Bearer <agent-token>`.

## Running Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
