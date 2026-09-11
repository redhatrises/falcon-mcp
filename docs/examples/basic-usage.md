<!-- meta:title Basic Usage -->
<!-- meta:description CLI examples for running the Falcon MCP Server with different transports. -->
<!-- meta:section examples -->
<!-- meta:link-base /falcon-mcp/ -->

These examples show how to run the Falcon MCP Server with the `falcon-mcp` binary (or `uvx falcon-mcp`).

## stdio Transport (Default)

The simplest way to run the server. MCP clients manage the process via stdin/stdout.

```bash
falcon-mcp
```

## SSE Transport

For web-based clients that connect via HTTP:

```bash
falcon-mcp --transport sse
```

Listens at `http://127.0.0.1:8000/sse` by default.

## Streamable HTTP Transport

The recommended transport for server deployments:

```bash
falcon-mcp --transport streamable-http --host 0.0.0.0 --port 8080 --api-key "$FALCON_MCP_API_KEY"
```

Listens at `http://0.0.0.0:8080/mcp`. Binding beyond loopback without `--api-key` exposes an
unauthenticated endpoint — always set an API key for non-local binds.

## Module Selection

Limit which modules are loaded:

```bash
falcon-mcp --modules detections,hosts,intel
```

## Credentials

Set CrowdStrike credentials via environment variables (or a `.env` file loaded by your process manager / `uvx --env-file`):

```bash
export FALCON_CLIENT_ID=your-client-id
export FALCON_CLIENT_SECRET=your-client-secret
# Optional region override
export FALCON_BASE_URL=https://api.us-2.crowdstrike.com

falcon-mcp --modules detections,hosts
```

See [CLI Commands](/falcon-mcp/usage/cli/) for the full flag reference.
