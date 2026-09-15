<!-- meta:title Installation -->
<!-- meta:description Install the Falcon MCP Server via uvx, npm, Go, GitHub Releases, or Docker. -->
<!-- meta:section getting-started -->
<!-- meta:link-base /falcon-mcp/ -->

The MCP server is a **Go binary**. Python and npm packages are wrappers around that binary.

## Prerequisites

- CrowdStrike Falcon API credentials ([see API Credentials](/falcon-mcp/getting-started/credentials))
- One of:
  - [`uv`](https://docs.astral.sh/uv/) or pip (downloads the GitHub Release binary)
  - Node.js / npm (`npx`)
  - A Go toolchain matching `go.mod`
  - Docker

Python 3.8+ is required **only** if you install via `uv` / `pip`. It is not required to run the server itself.

## Install using uv

```bash
uv tool install falcon-mcp
```

## Install using pip

```bash
pip install falcon-mcp
```

> [!TIP]
> If `falcon-mcp` isn't found after installation, update your shell `PATH`.

## Run without installing

You can run the server directly without a permanent install using `uvx` or `npx`:

```bash
uvx falcon-mcp
npx falcon-mcp
```

`uvx` is the recommended approach for editor integrations that already use uv.

## Install with Go

```bash
go install github.com/crowdstrike/falcon-mcp/cmd/falcon-mcp@latest
```

## GitHub Release binaries

Download the matching asset from [GitHub Releases](https://github.com/CrowdStrike/falcon-mcp/releases):

`falcon-mcp-{version}-{macos|linux|windows}-{x86_64|arm64}` (`.exe` suffix on Windows)

Verify the SHA-256 against `checksums.txt` in the same release.

## Docker

```bash
docker pull quay.io/crowdstrike/falcon-mcp:latest
```

See [Docker Deployment](/falcon-mcp/deployment/docker/).

> [!NOTE]
> If you just want to interact with falcon-mcp via an agent chat interface rather than running the server yourself, see the [Deployment](/falcon-mcp/deployment/docker/) options.

## Find it on a registry

falcon-mcp is published to public MCP catalogs for discovery and one-click setup in compatible clients:

- [MCP Registry](https://registry.modelcontextprotocol.io/?q=io.github.CrowdStrike%2Ffalcon-mcp&all=1)<!-- link:external -->
- [GitHub MCP Registry](https://github.com/mcp/CrowdStrike/falcon-mcp)<!-- link:external -->
- [Gemini CLI Extensions](https://geminicli.com/extensions/?name=CrowdStrikefalcon-mcp)<!-- link:external -->
