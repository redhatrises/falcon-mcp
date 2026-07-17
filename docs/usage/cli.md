<!-- meta:title CLI Commands -->
<!-- meta:description Command-line options for running the Falcon MCP Server. -->
<!-- meta:section usage -->
<!-- meta:link-base /falcon-mcp/ -->

## Basic Usage

Run the server with default settings (stdio transport):

```bash
falcon-mcp
```

Run with SSE transport:

```bash
falcon-mcp --transport sse
```

Run with streamable-http transport:

```bash
falcon-mcp --transport streamable-http
```

Run with streamable-http on a custom port:

```bash
falcon-mcp --transport streamable-http --host 0.0.0.0 --port 8080 --api-key your-secret-key
```

Run with stateless HTTP mode (for scalable deployments like AWS AgentCore):

```bash
falcon-mcp --transport streamable-http --stateless-http
```

Run with API key authentication:

```bash
falcon-mcp --transport streamable-http --api-key your-secret-key
```

> [!CAUTION]
> HTTP transports have no authentication by default. Binding to a non-loopback address such as
> `--host 0.0.0.0` exposes an unauthenticated server that anyone who can reach the port can drive with
> your CrowdStrike credentials. Keep the default loopback bind (`127.0.0.1`) for local use, and set
> `--api-key` whenever you bind wider. See
> [HTTP Transport Security](/falcon-mcp/getting-started/configuration/#http-transport-security).

## Module Selection

Enable specific modules by name (comma-separated):

```bash
falcon-mcp --modules detections,intel,spotlight,idp
```

Enable only one module:

```bash
falcon-mcp --modules detections
```

If no `--modules` flag is provided, all available modules are enabled.

## All Options

```text
falcon-mcp --help
```

| Flag | Env Variable | Default | Description |
|------|-------------|---------|-------------|
| `--transport` | `FALCON_MCP_TRANSPORT` | `stdio` | Transport method: `stdio`, `sse`, `streamable-http` |
| `--host` | `FALCON_MCP_HOST` | `127.0.0.1` | Host for HTTP transports |
| `--port` | `FALCON_MCP_PORT` | `8000` | Port for HTTP transports |
| `--modules` | `FALCON_MCP_MODULES` | all | Comma-separated list of modules to enable |
| `--debug` | `FALCON_MCP_DEBUG` | `false` | Enable debug logging |
| `--api-key` | `FALCON_MCP_API_KEY` | — | API key for HTTP transport auth |
| `--stateless-http` | `FALCON_MCP_STATELESS_HTTP` | `false` | Stateless mode for scalable deployments |
| `--member-cid` | `FALCON_MEMBER_CID` | — | Flight Control child CID |
| `--proxy` | `FALCON_PROXY_URL` | — | HTTP/HTTPS proxy for outbound API connections |
| `--dynamic` | `FALCON_MCP_DYNAMIC` | `false` | [Dynamic mode](/falcon-mcp/usage/dynamic-mode/): expose three tools instead of all module tools to reduce context usage |
| `--health-addr` | `FALCON_MCP_HEALTH_ADDR` | — | [Operational endpoint](#operational-endpoints): `host:port` for the `/healthz` liveness probe. Empty disables it. |
| `--metrics-addr` | `FALCON_MCP_METRICS_ADDR` | — | [Operational endpoint](#operational-endpoints): `host:port` for the `/metrics` (expvar) endpoint. Empty disables it. |
| `--pprof-addr` | `FALCON_MCP_PPROF_ADDR` | — | [Operational endpoint](#operational-endpoints): `host:port` for the `/debug/pprof/` profiling endpoints. Empty disables it. |

## Operational Endpoints

`falcon-mcp` can expose three optional HTTP endpoints for liveness probing,
metrics, and profiling. All three are **disabled by default** and **independent
of the MCP transport** — each is enabled only by supplying its own address, and
each works under any transport, including `stdio`.

| Endpoint | Flag / Env | Path | Purpose |
|----------|------------|------|---------|
| Health | `--health-addr` / `FALCON_MCP_HEALTH_ADDR` | `/healthz` | Liveness probe. Returns `200 ok` when the process is up. It does **not** check that CrowdStrike APIs are reachable. |
| Metrics | `--metrics-addr` / `FALCON_MCP_METRICS_ADDR` | `/metrics` | Go runtime metrics (`memstats`) as JSON via the stdlib `expvar` package. |
| Profiling | `--pprof-addr` / `FALCON_MCP_PPROF_ADDR` | `/debug/pprof/` | `net/http/pprof` profiling (heap, CPU, goroutine, trace). |

Each endpoint binds a **separate listener** so operators can expose, firewall,
and scope them individually — for example, exposing `/healthz` to an
orchestrator's probe while keeping profiling on loopback only.

```bash
# Health probe reachable by the orchestrator; profiling loopback-only.
falcon-mcp --transport streamable-http \
  --health-addr 0.0.0.0:6061 \
  --pprof-addr 127.0.0.1:6060
```

!!! warning "Metrics and profiling are debugging tools"
    The `/metrics` and `/debug/pprof/` endpoints are intended for **debugging
    and troubleshooting only**, not for continuous production exposure.
    `/debug/pprof/heap` dumps live process memory, and `/debug/pprof/profile`
    blocks the process while it captures a CPU profile. These endpoints are
    **unauthenticated**.

    Prefer binding `--pprof-addr` and `--metrics-addr` to a loopback address
    (`127.0.0.1:PORT`) and reaching them through an SSH tunnel or
    `kubectl port-forward`. If you must use a non-loopback address, **configure
    firewall rules** to restrict access to trusted hosts only.

## Using as a Library

You can also embed the server directly in Python:

```python
from falcon_mcp.server import FalconMCPServer

server = FalconMCPServer(
    base_url="https://api.us-2.crowdstrike.com",  # Optional
    debug=True,
    enabled_modules=["detections", "spotlight"],
    api_key="your-api-key"
)

# Run with stdio transport (default)
server.run()

# Or with a specific transport
server.run("streamable-http")
```

For enterprise deployments using secret management systems (HashiCorp Vault, AWS Secrets Manager, etc.), you can pass credentials directly:

```python
server = FalconMCPServer(
    client_id="your-client-id",
    client_secret="your-client-secret",
    base_url="https://api.us-2.crowdstrike.com",
    enabled_modules=["detections", "hosts"],
    proxy="http://proxy.corp.example.com:8080",
)
server.run()
```

When both direct parameters and environment variables are available, direct parameters take precedence.
