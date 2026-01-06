# Mythic MCP Server

A high-capability MCP server for Mythic C2 using the Mythic Python SDK. It exposes operator-grade tools for tasking, payloads, callbacks, files, credentials, operations, analytics, and real-time subscriptions.

## Quick start

1) Create and edit `config.yaml`:

```yaml
mythic:
  server_ip: "127.0.0.1"
  server_port: 7443
  ssl: true
  username: "mythic_admin"
  password: "mythic_password"
  apitoken: ""
  timeout: -1
  logging_level: 20

mcp:
  name: "mythic_mcp"
  instructions: "Mythic C2 operator tools for MCP"
```

2) Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3) Run the server (stdio transport by default):

```bash
python -m mythic_mcp --config ./config.yaml
```

## Notes

- The server logs into Mythic on startup using the SDK and keeps a session alive.
- If `apitoken` is provided, it is used instead of username/password.
- Tools are async and safe to use with MCP clients like Codex and Claude Code.

## Repo layout

- `mythic_mcp/server.py`: MCP server and tool definitions
- `mythic_mcp/config.py`: config loader
- `config.yaml`: template config
