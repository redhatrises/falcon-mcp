<!-- meta:title Go Port Diffs -->
<!-- meta:description Intentional behavioral differences between the Go falcon-mcp server and the former Python implementation. -->
<!-- meta:section development -->
<!-- meta:link-base /falcon-mcp/ -->

# Known diffs vs the former Python server

This branch ships **one Go MCP server**. `uvx` / PyPI and `npx` only download or vendor that binary. The notes below are the remaining, **intentional** differences so an upstream PR is not a surprise. Delete this page once the Go server is the only documented contract.

## Inventory (mechanical)

| Surface | Go (`go_port`) | Notes |
|---------|----------------|-------|
| Domain modules | 29 (`internal/modules`, via `go generate`) | Plus 3 built-in core tools (`falcon_check_connectivity`, `falcon_list_enabled_modules`, `falcon_list_enabled_tools`) |
| Tools | 166 domain + 3 core ≈ 169 `falcon_*` tools | Names and descriptions tracked 1:1; `TestGuideReferencesResolve` requires every `falcon://` URI in a served tool description to resolve under `--read-only` |
| Recon aggregate guides | Restored | `falcon://recon/notifications/aggregate-guide`, `falcon://recon/exposed-data-records/aggregate-guide` |

Core connectivity tools are not a separate `core` module package; they are registered in `internal/mcpserver`.

## Kept on purpose

### NGSIEM CQL errors

Python routed start/poll/timeout/cancel failures through a soft `_format_cql_error_response` envelope (guide + hint in the tool result). Go treats those as **Go errors** (the request did not complete). The CQL guide is attached only on the empty HTTP 200 path, which is where a bad query masquerades as success. See the package comment in `internal/modules/ngsiem/ngsiem.go`.

### IDP GraphQL `errors` on HTTP 200

`runGraphQL` treats a 200 body that includes a GraphQL `errors` array as **partial success** and returns `data`. That matches GraphQL's partial-response model. It is not turned into a protocol error. Python may fail closed; this port does not.

### Dynamic-mode Prometheus double-count

`--dynamic` records `falcon_execute_tool` on the served server **and** the dispatched tool name on the catalog server. Unknown client-supplied names use the label `tool="unknown"`. Documented on the metric Help text.

### `DetailFetchConcurrency`

Default remains **4**. The field exists on `config.Config`; there is no CLI flag.

## Runtime notes

### Startup OAuth

`falconapi.CheckConnectivity` runs in `serve` after client construction so bad credentials fail before the MCP listener comes up.

### Dynamic-mode progress

`falcon_execute_tool` copies the outer request's progress token and installs a progress sink on the catalog dispatch context so the **client** session sees progress notifications. If a client still sees none, the SDK did not forward the token; that is an SDK limitation, not a second FastMCP.

### Catalog `ClientSession` concurrency

Dynamic mode uses one shared in-process `*mcp.ClientSession` for every `falcon_execute_tool` call. stdio is a single client. HTTP/SSE may dispatch concurrently. Unit tests run with `go test -race`. The Go MCP SDK is assumed to allow concurrent `CallTool` on that session; if a race appears in production HTTP dynamic mode, serialize catalog `CallTool` rather than documenting around a crash.

### Toolchain and gofalcon

- `go 1.26.4` and `new(expr)`: keep unless CrowdStrike CI images cannot build it.
- `gofalcon` is a **pseudo-version** (`v0.22.1-0.20260909153957-2ca5ed2752fd`) because the port needs APIs not on a tagged release. Pin a tagged gofalcon before a 1.0 of falcon-mcp.

### E2E

`make test-e2e` is local/manual and needs `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET`. It is **not** a branch-ready CI gate. A credential-gated GHA job can come later.

## Release pipeline

Keep **release-please** (conventional commits → changelog PR → tag) plus **GoReleaser** (binaries + `checksums.txt`). Do not replace release-please with tag-only Go tooling — CrowdStrike already depends on conventional-commit changelogs.

Publishing is **OIDC only** (no org GitHub secrets / no `NPM_TOKEN`):

| Target | Auth |
|--------|------|
| GitHub Release assets | `github.token` + GoReleaser `release.mode: keep-existing` |
| PyPI (`python/` wrapper) | Trusted Publishing (`id-token: write`, environment `release`) |
| npm (`falcon-mcp` + six platform packages) | Trusted Publishing (`id-token: write`, environment `release`, Node 24 / npm ≥ 11.5.1) |
| MCP Registry | `mcp-publisher login github-oidc` |

Before the first npm release, configure a Trusted Publisher on npmjs.com for **each** package (`falcon-mcp` and `falcon-mcp-{macos,linux,windows}-{x86_64,arm64}`) pointing at workflow `release-please.yml` and environment `release`.

Version stamps for wrappers/registry files live in `release-please-config.json` / `.release-please-manifest.json`. The workflow only syncs derived files release-please does not own (`docs/changelog.md`, `python/uv.lock`).

The workflow stays on **release-please-action v3.7.13** (release-please ^15) until the manifest config is dry-run validated. Action v4 pins release-please ^17; past config-file pain often tracked that jump, not the action wrapper itself. To compare:

```bash
# After the config files are on a remote branch (release-please reads GitHub, not your working tree):
npx release-please@15.13.0 release-pr \
  --token="$(gh auth token)" \
  --repo-url=redhatrises/falcon-mcp \
  --target-branch=go_port \
  --dry-run --debug

npx release-please@17.11.2 release-pr \
  --token="$(gh auth token)" \
  --repo-url=redhatrises/falcon-mcp \
  --target-branch=go_port \
  --dry-run --debug
```

Or run the workflow’s `workflow_dispatch` → `dry_run=true` (defaults to 15.13.0; set `release_please_version=17.11.2` to preview v4).

## Out of scope (not blocking ready)

Comment-volume cleanup, Ginkgo→stdlib e2e rewrite, MIT headers on every file, snake_case package directories.
