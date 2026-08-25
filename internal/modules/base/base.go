// Package base provides the shared contract and helpers every falcon-mcp tool
// module reuses: the Module interface consumed by the registry, a tool
// registration wrapper that applies the "falcon_" name prefix and default
// read-only annotations, sentinel errors for typed classification, structured
// output envelopes, and a bounded concurrent two-step detail-fetch helper.
//
// Modules call typed gofalcon methods directly and classify typed errors with
// errors.As against the sentinels declared here, rather than routing calls
// through a dynamic dispatch layer or sniffing untyped responses for an error.
//
// # Modules consuming multiple APIs
//
// A module declares a minimal local interface over each gofalcon sub-client it
// consumes, next to its consumer, so handlers can be tested against a small fake.
// A module that needs more than one API declares one such interface per API and
// holds one struct field per API, named for the API rather than a generic "API":
//
//	type Module struct {
//		Incidents incidentsAPI
//		Behaviors behaviorsAPI
//		Logger    *slog.Logger
//	}
//
// Its Factory pulls each field off the shared client independently; two roles
// served by the same sub-client are assigned from the same registry.Deps.API
// field, while roles from different sub-clients are assigned from their own.
// Prefer this to merging methods into one combined interface, which would force
// an adapter whenever the methods span sub-clients. Single-API modules keep the
// unambiguous field name "API".
package base

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/errgroup"
)

// Module is the contract every tool module implements. It is intentionally
// small and declared next to its sole consumer, the server registry. Concrete
// module types are returned from their constructors; only the registry consumes
// this interface.
type Module interface {
	// Name reports the module's short name (e.g. "detections").
	Name() string
	// Description reports a one-line, human-readable summary of what the module
	// covers. It feeds the dynamic-mode falcon_list_enabled_modules output and
	// generated help text, so it should read as a sentence without a trailing
	// period (e.g. "Search, retrieve, and triage Falcon detections/alerts").
	Description() string
	// RegisterTools registers the module's tools into r. Each tool should be
	// registered via AddTool so the "falcon_" prefix is applied centrally. The
	// Registrar sink decides whether tools land on a live *mcp.Server (normal
	// mode) or in a catalog (dynamic mode).
	RegisterTools(r Registrar)
	// RegisterResources registers the module's MCP resources on s (e.g. FQL
	// guides). Each resource should be registered via TextResource so the
	// "falcon_" name prefix is applied centrally.
	RegisterResources(s *mcp.Server)
	// RegisterPrompts registers the module's MCP prompts on s (e.g. guided
	// FQL-filter builders). Each prompt should be registered via Prompt so the
	// "falcon_" name prefix is applied centrally. A module with no prompts
	// implements this as a no-op.
	RegisterPrompts(s *mcp.Server)
}

// ErrFQLSyntax classifies a Falcon 400-class error caused by an invalid FQL
// filter. Modules wrap the underlying typed gofalcon error with %w so callers
// can branch with errors.Is.
var ErrFQLSyntax = errors.New("base: invalid FQL syntax")

// ErrEmptyResult classifies a successful query that matched zero entities.
var ErrEmptyResult = errors.New("base: no matching results")

// namePrefix is prepended to every registered tool name, so a tool registered
// as "search_detections" is exposed as "falcon_search_detections".
const namePrefix = "falcon_"

// SchemaFor infers In's schema from its struct tags, then applies mutate to add
// constraints and defaults the tag syntax can't express. Panics on a schema
// error (a programming error caught at startup).
func SchemaFor[In any](mutate func(*jsonschema.Schema)) *jsonschema.Schema {
	s, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("base.SchemaFor[%T]: %v", *new(In), err))
	}
	if mutate != nil {
		mutate(s)
	}
	return s
}

// Enum constrains a schema property to allowed, deriving the JSON Schema enum
// from the same slice the handler validates against with slices.Contains so the
// two cannot drift. An empty def leaves the property with no default; otherwise
// def is advertised as the default and must itself be in allowed. Panics when
// the property is absent, when the property is not a string, when allowed is
// empty, or when def is not in allowed (all programming errors caught at
// startup).
func Enum(s *jsonschema.Schema, property string, allowed []string, def string) {
	prop, ok := s.Properties[property]
	if !ok {
		panic(fmt.Sprintf("base.Enum: no property %q in schema", property))
	}
	if prop.Type != "string" {
		panic(fmt.Sprintf("base.Enum: property %q has type %q, want string", property, prop.Type))
	}
	if len(allowed) == 0 {
		panic(fmt.Sprintf("base.Enum: property %q has no allowed values", property))
	}
	prop.Enum = make([]any, len(allowed))
	for i, v := range allowed {
		prop.Enum[i] = v
	}
	if def == "" {
		return
	}
	if !slices.Contains(allowed, def) {
		panic(fmt.Sprintf("base.Enum: property %q default %q is not in %v", property, def, allowed))
	}
	encoded, err := json.Marshal(def)
	if err != nil {
		panic(fmt.Sprintf("base.Enum: marshaling property %q default %q: %v", property, def, err))
	}
	prop.Default = encoded
}

// readOnlyAnnotations returns the default annotations applied to query tools:
// readOnlyHint=true, idempotentHint=true, openWorldHint=true, destructiveHint=false.
func readOnlyAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		IdempotentHint:  true,
		OpenWorldHint:   new(true),
		DestructiveHint: new(false),
	}
}

// MutatingAnnotations returns annotations for non-destructive mutators
// (create/update/action). All four MCP hints are set explicitly: the protocol
// defaults DestructiveHint to true when omitted, so a partial override would
// incorrectly advertise non-destructive tools as destructive. idempotent should
// be true when repeating the call with the same arguments has no additional
// effect (e.g. a set-membership tag update).
//
//	readOnlyHint=false, destructiveHint=false, openWorldHint=true
func MutatingAnnotations(idempotent bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		IdempotentHint:  idempotent,
		OpenWorldHint:   new(true),
		DestructiveHint: new(false),
	}
}

// DestructiveAnnotations returns annotations for tools that permanently remove
// or irreversibly alter data (e.g. delete). idempotent should be true when
// repeating the call with the same arguments has no additional effect (typical
// for delete-by-id).
//
//	readOnlyHint=false, destructiveHint=true, openWorldHint=true
func DestructiveAnnotations(idempotent bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		IdempotentHint:  idempotent,
		OpenWorldHint:   new(true),
		DestructiveHint: new(true),
	}
}

// AddTool registers a typed tool into r under the name "falcon_"+name. When
// tool.Annotations is nil the default read-only annotations are applied;
// mutating tools must pass MutatingAnnotations or DestructiveAnnotations so
// DestructiveHint is never left nil (MCP default true). The output schema is
// inferred from Out via inferOutputSchema so gofalcon's strfmt date types
// resolve correctly.
//
// AddTool resolves the In/Out generics up front and hands the Registrar a
// ToolEntry carrying an SDK-registration closure (mcp.AddTool, the SDK's own
// erasure) plus the input schema inferred from In. The sink registers the tool
// on its target server via that closure; the dynamic catalog additionally reads
// InputSchema for parameter display and search. There is no hand-copied erasure
// path — both modes route invocation through the SDK.
func AddTool[In, Out any](r Registrar, tool *mcp.Tool, handler mcp.ToolHandlerFor[In, Out]) {
	tool.Name = namePrefix + tool.Name
	if tool.Annotations == nil {
		tool.Annotations = readOnlyAnnotations()
	}
	if tool.OutputSchema == nil {
		if schema := inferOutputSchema[Out](); schema != nil {
			tool.OutputSchema = schema
		}
	}
	r.Add(ToolEntry{
		Tool:        tool,
		InputSchema: catalogInputSchema[In](tool),
		register:    func(s *mcp.Server) { mcp.AddTool(s, tool, handler) },
	})
}

// catalogInputSchema returns the schema the dynamic catalog exposes for a tool.
// A caller-provided tool.InputSchema is authoritative — the served tool uses it
// verbatim, so the catalog must match rather than re-infer a divergent one from
// In. Only when the caller omits it does the catalog fall back to inference.
func catalogInputSchema[In any](tool *mcp.Tool) *jsonschema.Schema {
	if s, ok := tool.InputSchema.(*jsonschema.Schema); ok && s != nil {
		return s
	}
	return inferInputSchema[In]()
}

// inferInputSchema returns the JSON Schema for In, or nil when In is any (no
// properties to describe) or reflection fails. It is the schema the dynamic
// catalog exposes as a tool's parameters and folds into its search corpus,
// mirroring what the SDK infers for the served tool via the same public
// jsonschema-go call.
func inferInputSchema[In any]() *jsonschema.Schema {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		return nil
	}
	return schema
}

// defaultResourceMIME is applied to text resources registered without an
// explicit MIME type. All current FQL guides are Markdown.
const defaultResourceMIME = "text/markdown"

// TextResource registers a static UTF-8 text resource on s. Its Name is
// prefixed with "falcon_" (matching the tool-name convention applied by
// AddTool), so a resource registered as "search_detections_fql_guide" is
// exposed as "falcon_search_detections_fql_guide". uri is used verbatim (no
// prefix). When mime is empty it defaults to text/markdown. The registered
// handler serves text verbatim, echoing the requested URI in the response.
func TextResource(s *mcp.Server, uri, name, description, mime, text string) {
	if mime == "" {
		mime = defaultResourceMIME
	}
	s.AddResource(&mcp.Resource{
		Name:        namePrefix + name,
		Description: description,
		URI:         uri,
		MIMEType:    mime,
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{URI: req.Params.URI, MIMEType: mime, Text: text},
			},
		}, nil
	})
}

// PromptParams describes a static MCP prompt registered via Prompt. It groups
// the descriptor fields so the handler stays a separate argument.
type PromptParams struct {
	// Name is the prompt name without the "falcon_" prefix, which Prompt adds.
	Name string
	// Title is an optional human-readable display name.
	Title string
	// Description is a one-line summary of what the prompt produces.
	Description string
	// Arguments declares the prompt's templating arguments (all optional to the
	// client unless marked Required).
	Arguments []*mcp.PromptArgument
}

// PromptRenderer builds the prompt's messages from the client-supplied
// arguments. It is called on each prompts/get request; args is never nil (an
// absent Arguments map arrives as an empty map).
type PromptRenderer func(args map[string]string) []*mcp.PromptMessage

// Prompt registers an MCP prompt on s under the name "falcon_"+p.Name, matching
// the tool- and resource-name convention applied by AddTool and TextResource.
// render is invoked per prompts/get to produce the messages from the request's
// arguments; the prompt's Description is echoed on the result.
func Prompt(s *mcp.Server, p PromptParams, render PromptRenderer) {
	s.AddPrompt(&mcp.Prompt{
		Name:        namePrefix + p.Name,
		Title:       p.Title,
		Description: p.Description,
		Arguments:   p.Arguments,
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		args := req.Params.Arguments
		if args == nil {
			args = map[string]string{}
		}
		return &mcp.GetPromptResult{
			Description: p.Description,
			Messages:    render(args),
		}, nil
	})
}

// JSON object. It is used to stop schema reflection from descending into
// gofalcon's payload models — see inferOutputSchema.
var opaqueRecordSchema = &jsonschema.Schema{Types: []string{"null", "object"}}

// inferOutputSchema builds the output JSON Schema for Out. It describes our own
// result envelope precisely (resources, total, filter_used, errors, …) but
// treats each resource record as an opaque open object rather than reflecting
// gofalcon's model type.
//
// gofalcon's payload models (e.g. models.DetectsAlert) are deliberately
// polymorphic: they carry an AdditionalProperties catch-all map that MarshalJSON
// flattens back to the top level, so a single Go type represents EPP, IDP, XDR,
// and CWPP alerts with materially different field sets. Reflecting that type
// yields a closed schema (additionalProperties:false) that rejects every real
// response carrying fields not modeled on the struct, and mis-types its embedded
// strfmt.DateTime fields as objects. Rather than patch gofalcon's reflection, we
// don't describe the record interior at all — the record is advertised as an
// open object and its contents pass through unvalidated.
//
// The record type is located via Out's Resources slice field and overridden
// through TypeSchemas. The element type is dereferenced first because the reflector
// consults TypeSchemas by the pointed-to type, not the pointer. Envelopes without a
// Resources field (e.g. ActionResult) are reflected as-is.
//
// Out == any yields a nil schema so the SDK falls back to its default (no
// output schema), matching its own handling of untyped output.
func inferOutputSchema[Out any]() *jsonschema.Schema {
	ot := reflect.TypeFor[Out]()
	if ot == reflect.TypeFor[any]() {
		return nil
	}

	// An any-typed field reflects to the JSON Schema boolean `true`. That is a
	// valid schema, but a boolean where a property schema is expected trips strict
	// MCP clients, which then drop the whole tools/list. Describe it as an opaque
	// object so the property carries a schema object instead. The remaining
	// any-typed output fields are the idp module's per-investigation result blocks;
	// each holds a JSON object, so an opaque object describes them accurately.
	typeSchemas := map[reflect.Type]*jsonschema.Schema{
		reflect.TypeFor[any](): opaqueRecordSchema,
	}
	if ot.Kind() == reflect.Struct {
		if f, ok := ot.FieldByName("Resources"); ok && f.Type.Kind() == reflect.Slice {
			elem := f.Type.Elem()
			for elem.Kind() == reflect.Pointer {
				elem = elem.Elem()
			}
			typeSchemas[elem] = opaqueRecordSchema
		}
	}

	schema, err := jsonschema.For[Out](&jsonschema.ForOptions{TypeSchemas: typeSchemas})
	if err != nil {
		// A reflection failure here is a programming error (an unrepresentable
		// Out type); fall back to the SDK's own inference, which will surface it.
		return nil
	}
	return schema
}

// EntitiesResult is the structured output envelope for tools that return a set
// of entities without an FQL filter context (detail lookups and host-group
// query/CRUD tools). It is a JSON object so the SDK can derive an output schema.
//
// Total is the number of records in this response, i.e. len(Resources). Detail
// lookups are assembled from multiple chunked API calls with no single meta
// total, so this response-level count is the only count available and reflects
// resolved-versus-requested records. This differs from SearchResult, which
// carries no Total because the authoritative match count for a paginated FQL
// search lives in Meta (meta.pagination.total).
type EntitiesResult[T any] struct {
	Resources []T   `json:"resources"`
	Total     int   `json:"total"`
	Meta      *Meta `json:"meta,omitempty"`
}

// Entities builds an EntitiesResult, normalizing a nil slice to empty.
func Entities[T any](resources []T) EntitiesResult[T] {
	if resources == nil {
		resources = []T{}
	}
	return EntitiesResult[T]{Resources: resources, Total: len(resources)}
}

// WithMeta returns r with the API's response metadata attached, normalized to the
// fixed Meta shape. A nil or nil-pointer meta, or one carrying nothing reportable,
// leaves the field unset. See normalizeMeta.
func (r EntitiesResult[T]) WithMeta(meta any) EntitiesResult[T] {
	r.Meta = normalizeMeta(meta)
	return r
}

// ActionResult is the structured output envelope for mutating tools that do
// not return entity records. Ok is always true on success; Hint carries an
// optional advisory message (e.g. closing a detection without a resolution tag).
// Partial is set only when a chunked mutation applied some batches and then a
// later batch failed, so the caller can retry just the unfinished IDs.
type ActionResult struct {
	Ok      bool            `json:"ok"`
	Hint    string          `json:"hint,omitempty"`
	Partial *PartialSuccess `json:"partial_success,omitempty"`
	Meta    *Meta           `json:"meta,omitempty"`
}

// PartialSuccess reports how far a chunked mutation progressed before a batch
// failed, so the caller can retry only the unfinished IDs. It is surfaced on a
// data result (Ok:false, nil Go error) rather than an error, because the applied
// batches are real state changes the caller must not lose.
type PartialSuccess struct {
	UpdatedIDs            []string `json:"updated_ids"`
	UpdatedCount          int      `json:"updated_count"`
	FailedAndRemainingIDs []string `json:"failed_and_remaining_ids"`
}

// WithMeta returns r with the API's response metadata attached, normalized to the
// fixed Meta shape. Mutating endpoints report no pagination, so in practice only
// query_time and trace_id survive. A nil or nil-pointer meta, or one carrying
// nothing reportable, leaves the field unset. See normalizeMeta.
func (r ActionResult) WithMeta(meta any) ActionResult {
	r.Meta = normalizeMeta(meta)
	return r
}

// SearchResult is the structured output envelope returned by the FQL search
// tools. It is generic over the resource type so each tool advertises an
// accurate output schema, and it is a JSON object (required for a derived
// output schema). A single shape covers three outcomes:
//   - success: Resources populated, Meta carrying the API pagination/counts.
//   - empty:   Resources is an empty (non-nil) slice.
//   - FQL error: Errors/FQLGuide/Hint populated (see FQLError); the tool still
//     returns a normal result, matching the server's data-not-protocol-error
//     contract for invalid filters.
//
// Match counts and the pagination cursor are not surfaced as dedicated fields;
// clients read them from Meta at meta.pagination.{total,next}, which carries the
// same shape on every endpoint (see Meta).
//
// Some endpoints leave the total null, so clients must iterate until resources
// comes back empty rather than relying on the count.
//
// The value is returned as the handler's typed Out, so the SDK marshals it once
// into StructuredContent as native JSON — no stringify-then-reparse round trip.
type SearchResult[T any] struct {
	Resources  []T              `json:"resources"`
	FilterUsed string           `json:"filter_used,omitempty"`
	Errors     []FQLErrorDetail `json:"errors,omitempty"`
	FQLGuide   string           `json:"fql_guide,omitempty"`
	Hint       string           `json:"hint,omitempty"`
	Meta       *Meta            `json:"meta,omitempty"`
}

// WithMeta returns r with the API's response metadata attached, normalized to the
// fixed Meta shape: the pagination cursor and count, the query duration, the trace
// ID, and the Spotlight quota. Endpoint-specific extras the caller cannot act on
// are dropped. A nil or nil-pointer meta, or one carrying nothing reportable,
// leaves the field unset. See normalizeMeta.
func (r SearchResult[T]) WithMeta(meta any) SearchResult[T] {
	r.Meta = normalizeMeta(meta)
	return r
}

// Found builds a success (or empty) SearchResult from fetched detail resources.
// A nil slice is normalized to an empty slice so the output is always a JSON
// array. Match counts and pagination are surfaced via WithMeta, not here.
func Found[T any](resources []T, filter string) SearchResult[T] {
	if resources == nil {
		resources = []T{}
	}
	return SearchResult[T]{Resources: resources, FilterUsed: filter}
}

// FQLError builds a SearchResult describing an invalid FQL filter, carrying the
// API error details and the module's FQL guide text. Resources is empty.
func FQLError[T any](details []FQLErrorDetail, filter, fqlGuide string) SearchResult[T] {
	return SearchResult[T]{
		Resources:  []T{},
		Errors:     details,
		FilterUsed: filter,
		FQLGuide:   fqlGuide,
		Hint:       "The provided FQL filter appears to be invalid. Review the fql_guide for correct syntax.",
	}
}

// FQLErrorDetail is one API error surfaced inside a SearchResult.
type FQLErrorDetail struct {
	Code    int32  `json:"code"`
	Message string `json:"message"`
}

// FQLErrorDetails flattens gofalcon MsaAPIError values into FQLErrorDetail,
// skipping nil entries and dereferencing the optional Code/Message pointers.
func FQLErrorDetails(errs []*models.MsaAPIError) []FQLErrorDetail {
	details := make([]FQLErrorDetail, 0, len(errs))
	for _, e := range errs {
		if e == nil {
			continue
		}
		var code int32
		if e.Code != nil {
			code = *e.Code
		}
		var msg string
		if e.Message != nil {
			msg = *e.Message
		}
		details = append(details, FQLErrorDetail{Code: code, Message: msg})
	}
	return details
}

// DetailFetcher fetches the detail records for a single chunk of IDs. It must be
// safe for concurrent use and must honor ctx cancellation.
type DetailFetcher[T any] func(ctx context.Context, ids []string) ([]T, error)

// ProgressFunc returns a chunk-progress callback suitable for
// FetchDetailsParams.Progress, or nil when the client did not request progress.
// It reports progress only when req carries a progress token (nil req, or an
// absent token, yields nil) — per the MCP spec, servers send progress
// notifications solely for requests that opted in with a token.
//
// The returned callback sends a best-effort progress/notification per completed
// chunk over req.Session; notification errors are ignored, as progress is
// telemetry and must never fail the tool call. It is safe for concurrent use.
func ProgressFunc(ctx context.Context, req *mcp.CallToolRequest) func(done, total int) {
	if req == nil || req.Session == nil || req.Params == nil {
		return nil
	}
	token := req.Params.GetProgressToken()
	if token == nil {
		return nil
	}
	session := req.Session
	return func(done, total int) {
		_ = session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Progress:      float64(done),
			Total:         float64(total),
		})
	}
}

// FetchDetailsParams configures a bounded concurrent two-step detail fetch.
type FetchDetailsParams[T any] struct {
	// IDs is the full set of entity IDs to fetch details for.
	IDs []string
	// ChunkSize is the maximum number of IDs a single detail call accepts.
	ChunkSize int
	// Concurrency bounds in-flight detail calls (rate-limit aware, not CPU-bound).
	Concurrency int
	// Fetch retrieves the details for one chunk.
	Fetch DetailFetcher[T]
	// KeyFn, when non-nil, returns an entity's ID. FetchDetails uses it to
	// reorder each chunk's results back into the requested ID order, restoring
	// the sort applied by the query step: some get-by-IDs endpoints return
	// entities in arbitrary order, silently discarding that sort. When nil,
	// results keep the order the fetcher returned.
	KeyFn func(T) string
	// Progress, when non-nil, is called once per chunk as it completes with the
	// running (done, total) chunk counts. It reports progress at chunk
	// granularity, not per record. It must be safe for concurrent use: on the
	// multi-chunk path chunks finish on separate goroutines. A single-chunk fetch
	// calls it once with (1, 1). It is not called when there are no IDs to fetch.
	Progress func(done, total int)
}

// FetchDetails fetches details for p.IDs, chunking when the set exceeds p.ChunkSize
// and fetching chunks concurrently under a single errgroup tied to ctx. Results
// are reassembled into a pre-sized slice indexed by chunk position, giving
// stable order without a mutex. A single chunk takes the plain
// sequential path with no goroutines spawned.
func FetchDetails[T any](ctx context.Context, p FetchDetailsParams[T]) ([]T, error) {
	if len(p.IDs) == 0 {
		return []T{}, nil
	}
	chunkSize := p.ChunkSize
	if chunkSize < 1 {
		chunkSize = len(p.IDs)
	}

	chunks := chunkIDs(p.IDs, chunkSize)
	if len(chunks) == 1 {
		res, err := p.Fetch(ctx, chunks[0])
		if err != nil {
			return nil, err
		}
		if p.Progress != nil {
			p.Progress(1, 1)
		}
		return reorderByIDs(chunks[0], res, p.KeyFn), nil
	}

	total := len(chunks)
	var done atomic.Int64
	perChunk := make([][]T, len(chunks))
	g, gctx := errgroup.WithContext(ctx)
	if p.Concurrency > 0 {
		g.SetLimit(p.Concurrency)
	}
	for i, chunk := range chunks {
		g.Go(func() error {
			res, err := p.Fetch(gctx, chunk)
			if err != nil {
				return fmt.Errorf("fetch details chunk %d: %w", i, err)
			}
			perChunk[i] = reorderByIDs(chunk, res, p.KeyFn)
			if p.Progress != nil {
				p.Progress(int(done.Add(1)), total)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	n := 0
	for _, res := range perChunk {
		n += len(res)
	}
	out := make([]T, 0, n)
	for _, res := range perChunk {
		out = append(out, res...)
	}
	return out, nil
}

// chunkIDs splits ids into consecutive slices of at most size elements. The
// returned slices share ids' backing array; callers must not mutate them.
func chunkIDs(ids []string, size int) [][]string {
	chunks := make([][]string, 0, (len(ids)+size-1)/size)
	for start := 0; start < len(ids); start += size {
		end := min(start+size, len(ids))
		chunks = append(chunks, ids[start:end])
	}
	return chunks
}

// reorderByIDs reorders entities to match the order of ids, keyed by key(entity).
// It restores the sort applied by a query step when a get-by-IDs endpoint returns
// entities in arbitrary order, and is a no-op when the endpoint already preserves
// order.
//
// Entities whose key is not in ids are appended in their original order and never
// dropped; ids with no matching entity are skipped. A keyless entity (key == "")
// is treated as not-in-ids and appended. When key is nil the entities are returned
// unchanged.
func reorderByIDs[T any](ids []string, entities []T, key func(T) string) []T {
	if key == nil || len(entities) == 0 {
		return entities
	}

	byID := make(map[string]T, len(entities))
	for _, e := range entities {
		if k := key(e); k != "" {
			if _, dup := byID[k]; !dup {
				byID[k] = e
			}
		}
	}

	out := make([]T, 0, len(entities))
	placed := make(map[string]struct{}, len(entities))
	for _, id := range ids {
		if e, ok := byID[id]; ok {
			if _, done := placed[id]; !done {
				out = append(out, e)
				placed[id] = struct{}{}
			}
		}
	}
	// Preserve entities not referenced by ids rather than dropping them.
	for _, e := range entities {
		k := key(e)
		if k == "" {
			out = append(out, e)
			continue
		}
		if _, done := placed[k]; !done {
			out = append(out, e)
		}
	}
	return out
}
