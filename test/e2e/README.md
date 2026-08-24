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

The current specs are labeled with `integration` plus a per-module label
(`hosts`, `detections`, `intel`, …). Most specs are read-only, but some drive
live **mutations** (create → find → delete round-trips) and carry an extra
`mutating` label. The MSSP routing spec carries an `mssp` label. Exclude the
mutating specs to keep a run non-destructive:

```sh
make test-e2e GINKGO_LABEL_FILTER="!mutating"       # read-only run
make test-e2e GINKGO_LABEL_FILTER="ioc && !mutating"
```

See the Ginkgo docs for the full label-filter grammar (`&&`, `||`, `!`,
parentheses).

### Mutating specs

Specs labeled `mutating` create a disposable resource (named
`falcon-mcp-e2e-*`), assert it is findable, and delete it. Cleanup is registered
with `DeferCleanup` the moment the resource is created, so it runs even if a
later assertion fails. Each mutating spec **skips** cleanly when the tenant's
credentials lack the required write scope, so a read-only tenant is safe. To run
them you need the write scopes listed below; to avoid any writes, filter with
`!mutating`.

### MSSP / Flight Control routing

The `mssp` spec verifies that a member CID routes calls to a child tenant. The
Go client bakes the member CID into the gofalcon client at build time (there is
no per-call `member_cid` argument), so the spec builds its own member-scoped
server and runs a read through it. It requires `FALCON_MEMBER_CID` set to a
valid child CID and skips when it is unset:

```sh
export FALCON_MEMBER_CID=...     # a valid child CID
make test-e2e GINKGO_LABEL_FILTER="mssp"
```

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
touches. Specs labeled `mutating` additionally require the write scope shown; a
spec that hits a missing scope or a tenant with no matching data **skips** with
a visible reason rather than failing.

| Module          | Scope                                        |
|-----------------|----------------------------------------------|
| detections      | Alerts: Read (+ Write for the tag round-trip)|
| hosts           | Hosts: Read                                  |
| intel           | Actors / Indicators / Reports (Falcon Intelligence): Read |
| spotlight       | Vulnerabilities: Read                        |
| quarantine      | Quarantined Files: Read                      |
| sensor_usage    | Sensor Usage: Read                           |
| recon           | Monitoring rules (Falcon Intelligence Recon): Read |
| data_protection | Data Protection: Read                        |
| host_groups     | Host Group: Read (+ Write for the round-trip)|
| ioc             | IOC Management: Read (+ Write for the round-trip) |
| custom_ioa      | Custom IOA: Read (+ Write for the round-trip)|
| correlation_rules | Correlation Rules: Read (+ Write for the round-trip) |
| cloud           | CSPM/Falcon Cloud Security: Read (+ Write for the suppression round-trip) |

The other module suites (cases, discover, firewall, idp, ngsiem, policies,
scheduled_reports, serverless, shield) require read access to their respective
resources; see each `test/e2e/<module>_test.go` for the tools it calls.

## Adding a module suite

The module specs live in `test/e2e/` (`package e2e`); the shared harness and
Ginkgo suite bootstrap live alongside them in the same package. Copy
`hosts_test.go` as a template:

1. New file `test/e2e/<module>_test.go`, `package e2e`.
2. `Describe("<module> module", Label("integration", "<module>"), func() { ... })`.
3. Use the shared helpers in `helpers_test.go` (`newSession`, `callTool`,
   `expectSearchReturnsDetails`, `skipIfEmpty`, …). No new production code and no
   per-suite setup — the shared server and one-time auth live in
   `e2e_suite_test.go`.

For a **mutating** round-trip, add `Label("mutating")` to the spec, generate a
disposable name with `uniqueTestName`, gate the create with `skipIfToolError`
(so a missing write scope skips), and register the delete in `DeferCleanup`
immediately after the create so it runs even on a later failure. Use `idsOf` to
assert the created resource appears in a search. See `ioc_test.go` or
`host_groups_test.go` as templates.
