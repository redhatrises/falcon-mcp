<!-- meta:title Go Module Development -->
<!-- meta:description Architectural reference and checklist for implementing Falcon MCP modules in Go. -->
<!-- meta:section development -->
<!-- meta:link-base /falcon-mcp/ -->

# Go Module Development

This is the architectural reference for the **Go** falcon-mcp server. Follow it when porting or adding tools, resources, and prompts. The Python guide (`module-development.md`) remains for the Python tree only.

**Design goal:** adding a module is copy-adapt of an existing package. The official Go MCP SDK owns schema inference, validation, and result packing; modules only supply typed handlers and gofalcon calls.

## Architecture

```
cmd/falcon-mcp                 process entry
internal/cli                   cobra flags, transport selection
internal/config                env/file config
internal/falcon                OAuth + gofalcon client
internal/mcpserver             assembles *mcp.Server, --modules filter, dynamic catalog
internal/modules/registry      Deps + Factory + Build
internal/modules/<name>        one package per domain module
internal/modules/base          Module contract, AddTool, envelopes, errors
```

**Rules:**

- Domain modules never import `internal/mcpserver` or `internal/cli`.
- Modules depend on `base`, `registry`, gofalcon sub-clients, and go-sdk / jsonschema-go as needed.
- No `init()` registration. Discovery is explicit: export `Factory`, run `go generate`.

### Module contract

```go
// internal/modules/base.Module
type Module interface {
    Name() string
    Description() string
    RegisterTools(r Registrar)
    RegisterResources(s *mcp.Server)
    RegisterPrompts(s *mcp.Server)
}
```

### Discovery

1. Create `internal/modules/<dir>/` with package-level:

   ```go
   var Factory registry.Factory = func(d registry.Deps) base.Module {
       return &Module{API: d.API.SomeClient, Logger: d.Logger}
   }
   ```

2. From repo root: `go generate ./...` (or `make generate`).

3. `tools/genmodules` rewrites `internal/mcpserver/factories_gen.go`. Packages missing `Factory` fail at generate time.

4. Server builds modules with `registry.Build(deps, moduleFactories())`, then filters by `--modules`.

### Normal vs dynamic mode

| Mode | Tools | Resources / prompts |
|------|--------|---------------------|
| Normal | Registered on the served `*mcp.Server` via `base.ServerRegistrar` | On served server |
| Dynamic | Registered on an internal catalog server; served surface is three meta-tools | Still on served server |

Implement tools only through `base.AddTool(r, …)`. The `Registrar` sink decides where they land. Do not special-case dynamic mode inside modules.

## Idiomatic Go MCP SDK usage

We use [`github.com/modelcontextprotocol/go-sdk`](https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp). Prefer the generic API.

| Concern | Do | Don't |
|--------|----|--------|
| Tool registration | `base.AddTool` → `mcp.AddTool[In, Out]` | Hand-rolled type erasure or raw map handlers |
| Handler signature | `func(ctx, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error)` | Python-style free kwargs / Pydantic fields |
| Success payload | Return typed `Out`; leave `*CallToolResult` nil | Manually build `Content` and re-marshal JSON |
| Soft FQL failure | `return nil, base.FQLError[T](…), nil` (data result) | Turn bad filters into protocol/`error` unless intentional |
| Hard failure | Return Go `error` / `*base.Error` | Success payloads shaped like `{"error": …}` |
| Input schema | Struct + `json` / `jsonschema` tags; `base.SchemaFor[In](mutate)` for bounds | Giant hand-written JSON schema blobs |
| Output schema | Let `base.AddTool` infer from `Out` (opaque records); list omits it (#376) | Reflect full polymorphic models / publish schemas on tools/list |
| Annotations | Omit for read-only; **use helpers for mutators** | Partial annotation structs (see below) |
| Names | Register unprefixed (`search_hosts`); base adds `falcon_` | Prefix at call sites |
| Resources | `base.TextResource` with `falcon://…` URI | FastMCP-specific types |
| Prompts | `base.Prompt` + renderer | Ad-hoc prompts without the name prefix |
| Progress | `base.ProgressFunc(ctx, req)` only when the client sent a token | Always notify |
| Cancellation | Pass `ctx` into gofalcon `*ParamsWithContext(ctx)` | Ignore context |

### Tool annotations (required reading)

MCP defaults **`destructiveHint` to true when omitted**. Incomplete mutator annotations therefore advertise non-destructive tools as destructive.

Always use the base helpers:

```go
// Read-only (default): omit Annotations; base.AddTool fills them in.

// Create / update / non-destructive action
Annotations: base.MutatingAnnotations(),

// Permanent delete / irreversible remove
Annotations: base.DestructiveAnnotations(true), // true if idempotent
```

| Helper | readOnly | destructive | idempotent | openWorld |
|--------|----------|-------------|------------|-----------|
| (default via AddTool) | true | false | true | true |
| `MutatingAnnotations()` | false | false | false | true |
| `DestructiveAnnotations(idempotent)` | false | true | param | true |

## Golden modules (clone these)

| Template | Package | Use when |
|----------|---------|----------|
| Read-only search + details | `internal/modules/hosts` | Query then hydrate by ID; FQL guide resource |
| FQL soft-error + prompt | `internal/modules/detections` | Bad FQL returns guide in result; optional prompts |
| Mutations | `internal/modules/host_groups` | Create/update/delete/action with annotation helpers |

### Package layout

```
internal/modules/<name>/
  <name>.go          // Module, Factory, local *API interface, Register*, search/get
  mutations.go       // optional: create/update/delete/action
  fql_guide.md       // optional: human-edited FQL docs
  fqlguide.go        // //go:generate genfqlguide
  prompt.go          // optional
  <name>_test.go     // fake API + table tests; no live Falcon
```

### Factory and local API interface

```go
var Factory registry.Factory = func(d registry.Deps) base.Module {
    return &Module{
        API:         d.API.Hosts,
        Concurrency: d.Concurrency,
        Logger:      d.Logger,
    }
}

// Narrow interface next to the consumer for unit tests.
type hostsAPI interface {
    QueryDevicesByFilter(...) (*..., error)
    PostDeviceDetailsV2(...) (*..., error)
}
```

Multi-API modules: one struct field per gofalcon sub-client (named for the API). Prefer that over one mega-interface. See the package comment on `internal/modules/base`.

### Shared helpers

| Helper | Path | When |
|--------|------|------|
| `base.AddTool` | `base/base.go` | Every tool |
| `base.SchemaFor` | same | min/max/default, rich descriptions |
| `base.MutatingAnnotations` / `DestructiveAnnotations` | same | Every mutator |
| `base.TextResource` / `base.Prompt` | same | FQL guides / guided prompts |
| `base.SearchResult` / `Found` / `FQLError` | same | FQL search tools |
| `base.Entities` / `ActionResult` | same | Details / mutators without entity lists |
| `base.FetchDetails` + `ProgressFunc` | same | Query-IDs → get-by-IDs |
| `base.APIError` + `base.Scope` | `errors.go`, `scopes.go` | Every gofalcon call |
| `registry.Factory` / `Deps` | `registry/` | Wiring |

### Search-tool algorithm

1. Normalize defaults (`limit == 0` → default).
2. Build gofalcon params with context.
3. Call query API.
4. If 400 FQL → `return nil, base.FQLError[T](details, filter, fqlGuide), nil`.
5. Else `base.APIError(err, resp, scopeRead)` → return error.
6. Empty IDs → `base.Found(empty, filter)`.
7. Else `base.FetchDetails` (chunk, concurrency, optional `KeyFn` reorder, progress).
8. `return nil, base.Found(details, filter), nil`.

Mutators: validate input → write scope → `Entities` or `ActionResult` → annotation helper.

### Scopes

Declare package-local scopes; pass them at each call site:

```go
var scopeHostsRead = base.Scope{Name: "Hosts", Read: true}
// ...
if e := base.APIError(err, resp, scopeHostsRead); e != nil {
    return nil, zero, e
}
```

Do not reintroduce a central Python-style operation→scope map unless a later pass proves shared need.

## Python → Go anti-patterns

| Python | Go |
|--------|----|
| `BaseModule` inheritance | Implement `base.Module` methods; no required embedding |
| `client.command("OpName", …)` | Typed gofalcon methods on a narrow local interface |
| Error **dicts** in success payloads | `base.APIError` → Go `error`; soft FQL → `SearchResult` |
| Central `API_SCOPE_REQUIREMENTS` | Package-local `Scope` values |
| `pkgutil` auto-discovery | `Factory` + `genmodules` |
| Pydantic `Field(ge=, …)` | `jsonschema` tags + `SchemaFor` mutate |
| `structured_output=False` free dicts | Typed `Out` envelopes |
| Resources under `falcon_mcp/resources/` | Co-locate `fql_guide.md` in the module package |

**Parity target:** tool names, descriptions, and client-visible behavior — not class hierarchy.

## Checklist: new module

- [ ] Package under `internal/modules/<name>/`
- [ ] `var Factory registry.Factory`
- [ ] `Name()` / `Description()` (description: one sentence, no trailing period)
- [ ] Local `*API` interface(s) over gofalcon sub-client(s)
- [ ] Scopes at each call site
- [ ] Tools via `base.AddTool` (annotation helpers for mutators)
- [ ] Input structs + `SchemaFor` where bounds/defaults/backticks need it
- [ ] Correct envelope: `SearchResult` / `EntitiesResult` / `ActionResult`
- [ ] FQL resource (`fql_guide.md` + `//go:generate`) if the module has FQL search
- [ ] Prompts only if the Python module had them
- [ ] Unit tests with fake API (include annotation registration tests for mutators)
- [ ] `go generate ./...` updates `factories_gen.go`
- [ ] Tool names and descriptions stay 1:1 with Python for client compatibility

## Porting order (remaining modules)

| Tier | Modules | Clone |
|------|---------|-------|
| A | `intel`, `spotlight`, `discover`, `sensor_usage`, `serverless` | `hosts` |
| B | `ioc`, `quarantine`, `recon`, `exclusions` | `detections` |
| C | `policies`, `firewall`, `custom_ioa`, `correlation_rules` | `host_groups` |
| D | `rtr`, `ngsiem`, `idp`, `cloud`, `cases`, `shield`, `data_protection`, `scheduled_reports` | special cases; multi-API or atypical envelopes |

Do **not** invent new base abstractions until Tier D proves the same gap twice.

## Commands

```bash
# Regenerate factories + embedded FQL guides
make generate
# or: go generate ./...

# Tests
make test
# or: go test -race ./...

# Build
make build
```

## See also

- Official Go SDK: <https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp>
- Python module guide (legacy tree): [module-development.md](module-development.md)
- Resource conventions (URI scheme shared with Python): [resource-development.md](resource-development.md)
