# Live end-to-end tests

This suite drives the **real** falcon-mcp server over an in-memory MCP transport
against a **real** CrowdStrike Falcon tenant. Each spec builds a client session,
calls tools (`falcon_search_hosts`, `falcon_search_detections`, …) through the
MCP protocol, and asserts on the structured result envelopes and the live API
responses.

It complements the stub-backed unit tests under `internal/`: those verify the
protocol wiring in-process with fake gofalcon clients, while this suite verifies
the tools actually work end-to-end against Falcon — catching wrong operation
names, method/parameter mismatches, two-step searches that return bare IDs
instead of full records, response-schema drift, and scope gaps.

## Running

The suite is **excluded from `make test`** and never runs in CI. Run it
explicitly:

```sh
export FALCON_CLIENT_ID=...      # required
export FALCON_CLIENT_SECRET=...  # required
export FALCON_CLOUD=us-2         # optional (autodiscover by default)
export FALCON_MEMBER_CID=...     # optional (MSSP)
export FALCON_BASE_URL=...       # optional (region host override)
export TIMEOUT=90s               # optional (per-spec deadline; default 60s)

make test-e2e
```

Without `FALCON_CLIENT_ID`/`FALCON_CLIENT_SECRET`, the whole suite **skips**
cleanly (it does not fail), so `go test ./...` on a machine without credentials
is safe. Credentials may also be provided via a local `.env`/exported shell as
usual — the suite reads them from the process environment.

### Selecting a subset

Specs are labeled per module. Filter with `GINKGO_LABEL_FILTER`:

```sh
make test-e2e GINKGO_LABEL_FILTER="detections"      # only detections
make test-e2e GINKGO_LABEL_FILTER="hosts || detections"
```

The current specs are all read-only and carry the `integration` label plus a
per-module label (`hosts`, `detections`). See the Ginkgo docs for the full
label-filter grammar (`&&`, `||`, `!`, parentheses).

### Logging returned records

`make test-e2e` runs verbosely (`-ginkgo.vv`), showing each spec and its skip
reason. To also print the records each tool call returns, set `LOG_RESULTS=1`:

```sh
make test-e2e LOG_RESULTS=1
```

Each call logs its arguments, the resource count, and one truncated single-line
JSON entry per resource. It is off by default and only surfaces under verbose
output (or on failure).

### Per-spec timeout

Each spec bounds its live API interaction with a deadline so a slow or
unreachable tenant fails fast instead of wedging the run. It defaults to 60s;
override it with `TIMEOUT` as a Go duration string:

```sh
make test-e2e TIMEOUT=2m
```

An unset, empty, unparseable, or non-positive value falls back to the default.

## Required API scopes

The credentials must have at least read access to the resources each module
touches:

| Module     | Scope        |
|------------|--------------|
| detections | Alerts: Read  |
| hosts      | Hosts: Read   |

A spec that hits a missing scope or a tenant with no matching data **skips** with
a visible reason rather than failing.

## Adding a module suite

Copy `hosts_test.go` as a template:

1. New file `test/e2e/<module>_test.go`, `package e2e`.
2. `Describe("<module> module", Label("integration", "<module>"), func() { ... })`.
3. Use the shared helpers in `helpers_test.go` (`newSession`, `callTool`,
   `expectSearchReturnsDetails`, `skipIfEmpty`, …). No new production code and no
   per-suite setup — the shared server and one-time auth live in
   `e2e_suite_test.go`.
