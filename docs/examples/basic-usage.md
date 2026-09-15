<!-- meta:title Basic Usage -->
<!-- meta:description Command-line examples for running the Falcon MCP Server. -->
<!-- meta:section examples -->
<!-- meta:link-base /falcon-mcp/ -->

These examples show how to run the Falcon MCP Server. The server is a Go binary (`falcon-mcp`); `uvx` and `npx` wrap that binary.

## stdio Transport (Default)

The simplest way to run the server. MCP clients manage the process via stdin/stdout.

```bash
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
# Optional region override:
# export FALCON_BASE_URL="https://api.us-2.crowdstrike.com"

falcon-mcp
# or: uvx falcon-mcp
# or: npx falcon-mcp
```

A `.env` file in the working directory is loaded automatically.

## SSE Transport

For web-based clients that connect via HTTP.

```bash
falcon-mcp --transport sse
```

Listens at `http://127.0.0.1:8000/sse`.

## Streamable HTTP Transport

The recommended transport for server deployments.

```bash
# Binding to 0.0.0.0 exposes the server on the network with no auth by default,
# so set --api-key to require an x-api-key header from callers.
falcon-mcp --transport streamable-http --host 0.0.0.0 --port 8080 --api-key "$FALCON_MCP_API_KEY"
```

Listens at `http://0.0.0.0:8080/mcp`.

## Direct Credentials (Secret Management)

For enterprise deployments using secret management systems (HashiCorp Vault, AWS Secrets Manager, etc.), export credentials (or pass flags) before starting the process:

```bash
export FALCON_CLIENT_ID="$(vault kv get -field=client_id crowdstrike)"
export FALCON_CLIENT_SECRET="$(vault kv get -field=client_secret crowdstrike)"
export FALCON_BASE_URL="https://api.us-2.crowdstrike.com"

falcon-mcp --modules detections,hosts
```

Flags (`--client-id`, `--client-secret`, `--base-url`) win over environment variables. See [CLI Commands](/falcon-mcp/usage/cli/).
