// Package exclusions implements a unified set of tools for managing CrowdStrike
// exclusions across four types — IOA, Machine Learning, Sensor Visibility, and
// Certificate-Based — behind a single exclusion_type discriminator. Per-type
// backends absorb the body, field, sort, and limit differences so the tool
// surface stays clean for the calling agent.
//
// Record-returning operations return the raw API JSON decoded to
// []map[string]any rather than typed gofalcon models: the four types' models are
// heterogeneous, and the ML model carries a codegen bug that hard-fails decoding
// of live responses (see rawclient.go). This also keeps the returned records 1:1
// with the Python falcon-mcp module, which returns raw API dictionaries.
package exclusions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/certificate_based_exclusions"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the exclusions module from shared deps. It wires one backend
// per exclusion type over the four gofalcon exclusion sub-clients. The generated
// aggregator (internal/mcpserver) collects it, so the module needs no init side
// effect. Detail fetches are single-call get-by-IDs, so it ignores
// Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		backends: map[string]backend{
			"ioa":               ioaBackend{c: d.API.IoaExclusions},
			"ml":                mlBackend{c: d.API.MlExclusions},
			"sensor_visibility": svBackend{c: d.API.SensorVisibilityExclusions},
			"certificate":       cbBackend{c: d.API.CertificateBasedExclusions},
		},
		certs:  d.API.CertificateBasedExclusions,
		Logger: d.Logger,
	}
}

// fqlGuideURI is the MCP resource URI serving the exclusions search FQL guide,
// mirroring falcon-mcp's falcon://exclusions/search/fql-guide.
const fqlGuideURI = "falcon://exclusions/search/fql-guide"

// exclusionTypes is the ordered set of discriminator values exposed to the agent.
var exclusionTypes = []string{"ioa", "ml", "sensor_visibility", "certificate"}

// limitCap is the per-type maximum page size (certificate caps at 100, others 500).
var limitCap = map[string]int64{
	"ioa":               500,
	"ml":                500,
	"sensor_visibility": 500,
	"certificate":       100,
}

// errInvalidInput classifies client-side validation failures (invalid type,
// missing required fields) so the handler returns a guiding data result rather
// than an opaque API error.
var errInvalidInput = errors.New("exclusions: invalid input")

// CrowdStrike API scopes required by this module's operations, surfaced on a 403
// via base.APIError. Certificate-based exclusions and the certificate lookup are
// governed by the Machine Learning Exclusions scope (per the Python module).
var (
	scopeIOARead  = base.Scope{Name: "IOA Exclusions", Read: true}
	scopeIOAWrite = base.Scope{Name: "IOA Exclusions", Write: true}
	scopeMLRead   = base.Scope{Name: "Machine Learning Exclusions", Read: true}
	scopeMLWrite  = base.Scope{Name: "Machine Learning Exclusions", Write: true}
	scopeSVRead   = base.Scope{Name: "Sensor Visibility Exclusions", Read: true}
	scopeSVWrite  = base.Scope{Name: "Sensor Visibility Exclusions", Write: true}
)

// readScope and writeScope map an exclusion type to its required API scope.
// Certificate operations use the ML scope (see the var block above).
func readScope(t string) base.Scope {
	switch t {
	case "ioa":
		return scopeIOARead
	case "sensor_visibility":
		return scopeSVRead
	default: // ml, certificate
		return scopeMLRead
	}
}

func writeScope(t string) base.Scope {
	switch t {
	case "ioa":
		return scopeIOAWrite
	case "sensor_visibility":
		return scopeSVWrite
	default: // ml, certificate
		return scopeMLWrite
	}
}

// Module registers the exclusions tools. It holds the per-type backends and the
// certificate sub-client used by get_certificate_details; handlers are stateless
// and reentrant. Logger must be non-nil.
type Module struct {
	backends map[string]backend
	certs    certificate_based_exclusions.ClientService
	Logger   *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "exclusions" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search, create, update, and delete Falcon IOA, ML, sensor visibility, and certificate-based exclusions"
}

// searchExclusionsSchema is the input schema for falcon_search_exclusions. It is
// inferred from SearchInput's struct tags, then a mutate func adds the limit
// bounds/default and offset minimum the tag syntax cannot express.
var searchExclusionsSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`100`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// RegisterTools registers the five exclusions tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_exclusions",
		Description: "Search IOA, machine learning, sensor visibility, or certificate-based " +
			"exclusions by name, value, scope, or timestamp. Select which API is queried with " +
			"exclusion_type. Consult falcon://exclusions/search/fql-guide before constructing " +
			"filter expressions — the available fields differ per type. Returns full exclusion " +
			"records including id, scope, and timestamps.",
		InputSchema: searchExclusionsSchema,
	}, m.searchExclusions)

	base.AddTool(r, &mcp.Tool{
		Name: "create_exclusion",
		Description: "Create an exclusion of the given exclusion_type. 'ioa' needs name, pattern_id, " +
			"ifn_regex, and cl_regex; 'ml' and 'sensor_visibility' need value (sensor_visibility also " +
			"needs host_groups); 'certificate' needs name, certificate, and status. Returns the created " +
			"exclusion record(s).",
		Annotations: base.MutatingAnnotations(),
	}, m.createExclusion)

	base.AddTool(r, &mcp.Tool{
		Name: "update_exclusion",
		Description: "Update an existing exclusion of the given exclusion_type. Provide the id plus the " +
			"same fields used when creating that type. All four types update via HTTP PATCH. Returns the " +
			"updated exclusion record(s).",
		Annotations: base.MutatingAnnotations(),
	}, m.updateExclusion)

	base.AddTool(r, &mcp.Tool{
		Name: "delete_exclusions",
		Description: "Delete one or more exclusions of the given exclusion_type by ID, with an optional " +
			"audit comment. Idempotent.",
		Annotations: base.DestructiveAnnotations(true),
	}, m.deleteExclusions)

	base.AddTool(r, &mcp.Tool{
		Name: "get_certificate_details",
		Description: "Retrieve the code-signing certificate metadata for a file by SHA256 (issuer, subject, " +
			"serial, thumbprint, validity window). Use this as the pre-flight lookup before building a " +
			"certificate-based exclusion, then pass the result as the certificate argument to " +
			"falcon_create_exclusion. Returns certificate metadata for the given hash.",
	}, m.getCertificateDetails)
}

// RegisterResources publishes the exclusions search FQL guide as an MCP resource,
// mirroring falcon-mcp's falcon://exclusions/search/fql-guide resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_exclusions_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_exclusions` tool.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the exclusions module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_exclusions.
type SearchInput struct {
	ExclusionType string `json:"exclusion_type" jsonschema:"exclusion type to search: ioa, ml, sensor_visibility, or certificate"`
	Filter        string `json:"filter,omitempty" jsonschema:"FQL filter expression. See falcon://exclusions/search/fql-guide for syntax (fields vary by type)."`
	Limit         int    `json:"limit,omitempty" jsonschema:"maximum exclusions to return; capped at 100 for certificate, 500 otherwise"`
	Offset        int    `json:"offset,omitempty" jsonschema:"starting index of the result set"`
	Sort          string `json:"sort,omitempty" jsonschema:"FQL sort. A .desc direction is added automatically for ioa/ml/sensor_visibility when omitted."`
}

func (m *Module) searchExclusions(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[map[string]any], error) {
	var zero base.SearchResult[map[string]any]
	b, ok := m.backends[in.ExclusionType]
	if !ok {
		return nil, zero, invalidType(in.ExclusionType)
	}
	m.Logger.Debug("search_exclusions", "type", in.ExclusionType, "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	args := queryArgs{
		filter: in.Filter,
		sort:   normalizeSort(in.ExclusionType, in.Sort),
		limit:  clampLimit(in.ExclusionType, in.Limit),
	}
	if in.Offset != 0 {
		off := int64(in.Offset)
		args.offset = &off
	}

	ids, meta, err := b.query(ctx, args)
	if err != nil {
		if details, isFQL := b.classifyFQL(err); isFQL {
			return nil, base.FQLError[map[string]any](details, in.Filter, fqlGuide), nil
		}
		if e := base.APIError(err, nil, readScope(in.ExclusionType)); e != nil {
			return nil, zero, e
		}
	}
	if len(ids) == 0 {
		return nil, base.Found([]map[string]any{}, in.Filter).WithMeta(meta), nil
	}

	body, err := b.getRaw(ctx, ids)
	if err != nil {
		if e := base.APIError(err, nil, readScope(in.ExclusionType)); e != nil {
			return nil, zero, e
		}
	}
	records, _, err := decodeResources(body)
	if err != nil {
		return nil, zero, err
	}
	// Restore the query-step sort order in case the get endpoint reorders results.
	records = reorderByID(ids, records)
	m.Logger.Debug("search_exclusions complete", "type", in.ExclusionType, "matched", len(records))
	return nil, base.Found(records, in.Filter).WithMeta(meta), nil
}

// getCertificateDetails looks up code-signing certificate metadata for a file by
// SHA256. Its gofalcon model has no codegen bug, so the typed response is decoded
// through JSON round-trip into the uniform map record shape.
type CertDetailsInput struct {
	SHA256 string `json:"sha256" jsonschema:"SHA256 hash of the file whose code-signing certificate should be looked up"`
}

func (m *Module) getCertificateDetails(ctx context.Context, _ *mcp.CallToolRequest, in CertDetailsInput) (*mcp.CallToolResult, base.EntitiesResult[map[string]any], error) {
	var zero base.EntitiesResult[map[string]any]
	if in.SHA256 == "" {
		return nil, zero, wrapInvalid("get certificate details", "sha256 must not be empty")
	}
	m.Logger.Debug("get_certificate_details", "sha256", in.SHA256)

	// CertificatesGetV1 takes a SINGULAR string id, not a slice.
	p := certificate_based_exclusions.NewCertificatesGetV1ParamsWithContext(ctx)
	p.Ids = in.SHA256
	resp, err := m.certs.CertificatesGetV1(p)
	if e := base.APIError(err, resp, scopeMLRead); e != nil {
		return nil, zero, e
	}
	records, err := modelsToMaps(resp.Payload.Resources)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Entities(records).WithMeta(resp.Payload.Meta), nil
}

// decodeResources extracts the "resources" array and the raw "meta" object from
// a raw exclusion response body. Records decode into uniform map records; meta is
// returned verbatim (as map[string]any) for passthrough, or nil when absent so
// base.*.WithMeta omits it. An empty body or absent resources yields an empty
// (non-nil) slice, not an error.
func decodeResources(body []byte) ([]map[string]any, any, error) {
	if len(body) == 0 {
		return []map[string]any{}, nil, nil
	}
	var env struct {
		Resources []map[string]any `json:"resources"`
		Meta      map[string]any   `json:"meta"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, fmt.Errorf("decode exclusions response: %w", err)
	}
	var meta any
	if env.Meta != nil {
		meta = env.Meta
	}
	if env.Resources == nil {
		return []map[string]any{}, meta, nil
	}
	return env.Resources, meta, nil
}

// modelsToMaps marshals typed gofalcon records and unmarshals them back into
// uniform map records, so get_certificate_details returns the same shape as the
// raw-capture paths without depending on the certificate model's field layout.
func modelsToMaps[T any](in []T) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(in))
	for _, rec := range in {
		b, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("encode certificate record: %w", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("decode certificate record: %w", err)
		}
		out = append(out, m)
	}
	return out, nil
}

// reorderByID reorders records to match the query-step id order, keyed by each
// record's "id" field. Records without a string id, or whose id is not in ids,
// are appended in their original order and never dropped.
func reorderByID(ids []string, records []map[string]any) []map[string]any {
	if len(records) == 0 {
		return records
	}
	byID := make(map[string]map[string]any, len(records))
	for _, rec := range records {
		if id, ok := rec["id"].(string); ok && id != "" {
			if _, dup := byID[id]; !dup {
				byID[id] = rec
			}
		}
	}
	out := make([]map[string]any, 0, len(records))
	placed := make(map[string]struct{}, len(records))
	for _, id := range ids {
		if rec, ok := byID[id]; ok {
			if _, done := placed[id]; !done {
				out = append(out, rec)
				placed[id] = struct{}{}
			}
		}
	}
	for _, rec := range records {
		id, _ := rec["id"].(string)
		if id == "" {
			out = append(out, rec)
			continue
		}
		if _, done := placed[id]; !done {
			out = append(out, rec)
		}
	}
	return out
}

// normalizeSort appends a .desc direction for the types that require one. IOA,
// ML, and Sensor Visibility reject a bare field name; certificate tolerates it
// and is passed through unchanged.
func normalizeSort(exclusionType, sort string) string {
	if sort == "" || exclusionType == "certificate" {
		return sort
	}
	lowered := strings.ToLower(sort)
	for _, suffix := range []string{".asc", ".desc", "|asc", "|desc"} {
		if strings.HasSuffix(lowered, suffix) {
			return sort
		}
	}
	return sort + ".desc"
}

// clampLimit clamps limit to the per-type cap, defaulting to 100 when unset.
func clampLimit(exclusionType string, limit int) int64 {
	if limit <= 0 {
		limit = 100
	}
	if maxLimit, ok := limitCap[exclusionType]; ok && int64(limit) > maxLimit {
		return maxLimit
	}
	return int64(limit)
}

// invalidType builds the guiding error returned for an unknown exclusion_type.
func invalidType(t string) error {
	return fmt.Errorf("exclusions: %w: invalid exclusion_type %q (want one of %v)", errInvalidInput, t, exclusionTypes)
}

// wrapInvalid builds an errInvalidInput-wrapped error for op with detail.
func wrapInvalid(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, errInvalidInput, detail)
}

// errorsAs is a thin wrapper over errors.As, kept in this package so backends.go
// can classify typed 400s without importing errors directly at every call site.
func errorsAs(err error, target any) bool { return errors.As(err, target) }
