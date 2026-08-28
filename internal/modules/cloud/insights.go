package cloud

import (
	"context"
	"sort"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_assets"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// definitionsDefaultLimit is the default page size for the client-side insight
// definition catalog. The live catalog is well under this, so the default
// returns every definition; the cap bounds the response if the catalog grows.
const definitionsDefaultLimit = 200

// --- search_cloud_insights ---

// SearchCloudInsightsInput is the input for falcon_search_cloud_insights.
type SearchCloudInsightsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter. See the fql-guide resource for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of assets to query"`
	After  string `json:"after,omitempty" jsonschema:"pagination token from a previous response; use with limit to page results"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. updated_at.desc, resource_name.asc)"`
}

var searchCloudInsightsSchema = base.SchemaFor[SearchCloudInsightsInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = cloudInsightsFilterDescription
	s.Properties["sort"].Description = cloudInsightsSortDescription
	s.Properties["after"].Description = cloudInsightsAfterDescription
	limitBounds(500, 100)(s)
})

// CloudInsightsSearchResult is the structured output for falcon_search_cloud_insights.
// It mirrors base.SearchResult but adds the auto-filter reporting keys and an
// empty-catalog message. A dedicated Resources slice keeps output-schema
// inference working (base infers the record schema from this field).
type CloudInsightsSearchResult struct {
	Resources              []map[string]any      `json:"resources"`
	FilterUsed             string                `json:"filter_used,omitempty"`
	Errors                 []base.FQLErrorDetail `json:"errors,omitempty"`
	FQLGuide               string                `json:"fql_guide,omitempty"`
	Hint                   string                `json:"hint,omitempty"`
	Message                string                `json:"message,omitempty"`
	AutoFilterApplied      bool                  `json:"auto_filter_applied,omitempty"`
	AutoFilterInsightCount int                   `json:"auto_filter_insight_count,omitempty"`
	Meta                   *base.Meta            `json:"meta,omitempty"`
}

// searchCloudInsights searches assets carrying insights via FQL, returning one
// record per asset with a nested insights array. When the caller omits filter,
// it auto-scopes the query to every known insight ID from the Policy Framework
// catalog (a wildcard does not work here) and reports the auto-filter on the
// response. The query endpoint validates FQL fields server-side and returns a
// typed 400 for an unknown field.
func (m *Module) searchCloudInsights(ctx context.Context, req *mcp.CallToolRequest, in SearchCloudInsightsInput) (*mcp.CallToolResult, CloudInsightsSearchResult, error) {
	var zero CloudInsightsSearchResult
	m.Logger.Debug("search_cloud_insights", "filter", in.Filter, "limit", in.Limit, "after", in.After, "sort", in.Sort)

	effective, autoCount, ok, err := m.buildInsightFilter(ctx, in.Filter)
	if err != nil {
		return nil, zero, err
	}
	if !ok {
		return nil, CloudInsightsSearchResult{
			Resources: []map[string]any{},
			Message:   "No insight definitions found in the Policy Framework catalog. The catalog may be empty or unavailable.",
		}, nil
	}

	params := cloud_security_assets.NewCloudSecurityAssetsQueriesParamsWithContext(ctx)
	limit := int64(in.Limit)
	if limit == 0 {
		limit = 100
	}
	params.Limit = &limit
	params.Filter = &effective
	if in.After != "" {
		params.After = &in.After
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	qresp, err := m.Assets.CloudSecurityAssetsQueries(params)
	if details, bad := assetsFQLBadRequest(err); bad {
		// The expanded filter is what the API rejected, so echo it rather than
		// the caller's (possibly absent) one.
		fq := base.FQLError[map[string]any](details, effective, cloudInsightsFQLGuide)
		return nil, CloudInsightsSearchResult{
			Resources:  fq.Resources,
			FilterUsed: fq.FilterUsed,
			Errors:     fq.Errors,
			FQLGuide:   fq.FQLGuide,
			Hint:       fq.Hint,
		}, nil
	}
	if e := base.APIError(err, qresp, scopeAssetsRead); e != nil {
		return nil, zero, e
	}

	ids := qresp.Payload.Resources
	if len(ids) == 0 {
		return nil, m.autoFilterNote(CloudInsightsSearchResult{
			Resources:  []map[string]any{},
			FilterUsed: in.Filter,
			Meta:       base.NormalizedMeta(qresp.Payload.Meta),
		}, in.Filter, autoCount), nil
	}

	got, err := m.fetchCSPMAssetDetails(ctx, base.ProgressFunc(ctx, req), ids)
	if err != nil {
		return nil, zero, err
	}

	records := groupInsightsByAsset(got)
	return nil, m.autoFilterNote(CloudInsightsSearchResult{
		Resources:  records,
		FilterUsed: in.Filter,
		Meta:       base.NormalizedMeta(qresp.Payload.Meta),
	}, in.Filter, autoCount), nil
}

// autoFilterNote flags that the tool supplied the filter itself, without echoing
// it. filter_used stays the caller's filter (empty when omitted); the fact of
// auto-scoping is reported as two small keys rather than restating the generated
// insights.id list, which the caller did not ask for.
func (m *Module) autoFilterNote(res CloudInsightsSearchResult, callerFilter string, autoCount int) CloudInsightsSearchResult {
	if callerFilter == "" {
		res.AutoFilterApplied = true
		res.AutoFilterInsightCount = autoCount
	}
	return res
}

// --- get_cloud_asset_insights ---

// GetCloudAssetInsightsInput is the input for falcon_get_cloud_asset_insights.
type GetCloudAssetInsightsInput struct {
	AssetIDs []string `json:"asset_ids" jsonschema:"One or more cloud ASSET IDs (not insight IDs) to retrieve insights for. These are the asset_id values from falcon_search_cloud_insights or the id field from falcon_search_cspm_assets."`
}

// getCloudAssetInsights returns each asset's complete cloud_context.insights —
// both the external insight instances and the richer details map — plus asset
// context, for the given asset IDs. One record per requested asset that has
// insight data.
func (m *Module) getCloudAssetInsights(ctx context.Context, req *mcp.CallToolRequest, in GetCloudAssetInsightsInput) (*mcp.CallToolResult, base.EntitiesResult[map[string]any], error) {
	var zero base.EntitiesResult[map[string]any]
	if len(in.AssetIDs) == 0 {
		return nil, zero, base.InvalidInput("get cloud asset insights", "asset_ids must not be empty")
	}
	m.Logger.Debug("get_cloud_asset_insights", "asset_ids", len(in.AssetIDs))

	got, err := m.fetchCSPMAssetDetails(ctx, base.ProgressFunc(ctx, req), in.AssetIDs)
	if err != nil {
		return nil, zero, err
	}

	records := make([]map[string]any, 0, len(got))
	for _, res := range got {
		if res == nil || res.CloudContext == nil || res.CloudContext.Insights == nil {
			continue
		}
		rec := assetContext(res)
		rec["insights"] = res.CloudContext.Insights
		records = append(records, rec)
	}
	return nil, base.Entities(records), nil
}

// --- list_cloud_insight_definitions ---

// ListInsightDefinitionsInput is the input for falcon_list_cloud_insight_definitions.
type ListInsightDefinitionsInput struct {
	Categories []string `json:"categories,omitempty" jsonschema:"Filter to specific categories. Case-insensitive. Omit to return all categories."`
	Limit      int      `json:"limit,omitempty" jsonschema:"maximum number of definitions to return"`
	Offset     int      `json:"offset,omitempty" jsonschema:"number of definitions to skip before returning results"`
}

var listInsightDefinitionsSchema = base.SchemaFor[ListInsightDefinitionsInput](func(s *jsonschema.Schema) {
	s.Properties["categories"].Description = insightDefinitionsCategoriesDescription
	limitBounds(500, definitionsDefaultLimit)(s)
})

// listCloudInsightDefinitions returns the insight definition catalog,
// deduplicated by insight_id, optionally filtered by category, and client-side
// paged. pagination.total is an exact count because the catalog is assembled and
// counted locally rather than server-paged.
func (m *Module) listCloudInsightDefinitions(ctx context.Context, _ *mcp.CallToolRequest, in ListInsightDefinitionsInput) (*mcp.CallToolResult, base.EntitiesResult[map[string]any], error) {
	var zero base.EntitiesResult[map[string]any]
	m.Logger.Debug("list_cloud_insight_definitions", "categories", in.Categories, "limit", in.Limit, "offset", in.Offset)

	defs, err := m.getInsightDefinitions(ctx)
	if err != nil {
		return nil, zero, err
	}

	if len(in.Categories) > 0 {
		want := make(map[string]struct{}, len(in.Categories))
		for _, c := range in.Categories {
			want[strings.ToLower(c)] = struct{}{}
		}
		var filtered []map[string]any
		for _, e := range defs {
			cat, _ := e["category"].(string)
			if _, ok := want[strings.ToLower(cat)]; ok {
				filtered = append(filtered, e)
			}
		}
		defs = filtered
	}

	limit := in.Limit
	if limit == 0 {
		limit = definitionsDefaultLimit
	}
	offset := in.Offset
	total := len(defs)

	start := min(offset, total)
	end := min(start+limit, total)
	page := defs[start:end]
	if page == nil {
		page = []map[string]any{}
	}

	res := base.Entities(page)
	t, o, l := int64(total), int64(offset), int64(limit)
	res.Meta = &base.Meta{Pagination: &base.Paging{Total: &t, Offset: &o, Limit: &l}}
	return nil, res, nil
}

// --- shared helpers ---

// fetchCSPMAssetDetails hydrates asset IDs into full CSPM asset entities through
// the get-by-IDs endpoint, chunking to the endpoint's per-request ID limit and
// restoring the requested order.
func (m *Module) fetchCSPMAssetDetails(ctx context.Context, progress func(done, total int), ids []string) ([]*models.ResourcesCloudResource, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.ResourcesCloudResource]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    progress,
		Fetch: func(ctx context.Context, chunk []string) ([]*models.ResourcesCloudResource, error) {
			p := cloud_security_assets.NewCloudSecurityAssetsEntitiesGetParamsWithContext(ctx)
			p.Ids = chunk
			resp, err := m.Assets.CloudSecurityAssetsEntitiesGet(p)
			if e := base.APIError(err, resp, scopeAssetsRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		// The get endpoint may reorder results; restore the query step's order.
		// Field verified against the live API: id.
		KeyFn: func(a *models.ResourcesCloudResource) string {
			if a == nil {
				return ""
			}
			return a.ID
		},
	})
}

// assetContext extracts the common asset identity fields shared by both insight
// tools' output.
func assetContext(asset *models.ResourcesCloudResource) map[string]any {
	return map[string]any{
		"asset_id":         asset.ID,
		"asset_name":       asset.ResourceName,
		"asset_type":       asset.ResourceType,
		"cloud_provider":   asset.CloudProvider,
		"region":           asset.Region,
		"account_id":       asset.AccountID,
		"account_name":     asset.AccountName,
		"service_category": asset.ServiceCategory,
	}
}

// insightValue reads an insight instance's single value from the one typed value
// field the API populated, checking each in a fixed order so the result is
// deterministic. A nil pointer means the field is unset. StringListValue has no
// pointer wrapper, so a nil slice signals absence.
func insightValue(ext *models.InsightsExternal) any {
	switch {
	case ext.BooleanValue != nil:
		return *ext.BooleanValue
	case ext.StringValue != nil:
		return *ext.StringValue
	case ext.IntegerValue != nil:
		return *ext.IntegerValue
	case ext.DateValue != nil:
		return *ext.DateValue
	case ext.StringListValue != nil:
		return ext.StringListValue
	default:
		return nil
	}
}

// groupInsightsByAsset groups insight instances by asset, one record per asset.
// Assets with no well-formed insight entries are skipped. Each entry carries a
// null category deliberately: the per-insight category lives in the Policy
// Framework catalog, not on the asset record, and resolving it here would add a
// PFM round-trip to every search. Use falcon_list_cloud_insight_definitions to
// map insight_id to category.
func groupInsightsByAsset(assets []*models.ResourcesCloudResource) []map[string]any {
	records := make([]map[string]any, 0, len(assets))
	for _, asset := range assets {
		if asset == nil || asset.CloudContext == nil || asset.CloudContext.Insights == nil {
			continue
		}

		var assetInsights []map[string]any
		for _, ext := range asset.CloudContext.Insights.External {
			if ext == nil || ext.ID == nil {
				continue
			}
			assetInsights = append(assetInsights, map[string]any{
				"insight_id": *ext.ID,
				"category":   nil,
				"value":      insightValue(ext),
				"rule_id":    ext.RuleID,
			})
		}
		if len(assetInsights) == 0 {
			continue
		}
		rec := assetContext(asset)
		rec["insights"] = assetInsights
		records = append(records, rec)
	}
	return records
}

// --- insight definitions catalog ---

// insightMergeEntry accumulates the per-insight_id fields merged across the
// multiple Policy Framework rule instances (one per resource type) that share an
// insight_id. category and name are taken from the first rule seen, because an
// insight_id maps to exactly one of each.
type insightMergeEntry struct {
	insightID     string
	category      string
	name          string
	description   string
	providers     map[string]struct{}
	resourceTypes map[string]struct{}
	controlKeys   map[string]struct{}
	controls      []map[string]any
}

// buildInsightFilter returns the effective FQL filter for the asset query and
// how many insight IDs it names. When the caller supplies a filter it is used
// verbatim (count 0). When the caller omits it, every known insight ID is
// fetched from the catalog and an explicit insights.id:[...] expression is built
// — a wildcard does not work, because the FQL layer only rewrites explicit
// insights.id expressions to the internal ruleId field. ok is false only when
// the catalog is empty (the no-results message path).
func (m *Module) buildInsightFilter(ctx context.Context, callerFilter string) (effective string, count int, ok bool, err error) {
	if callerFilter != "" {
		return callerFilter, 0, true, nil
	}

	rules, err := m.fetchPFMRules(ctx)
	if err != nil {
		return "", 0, false, err
	}

	seen := make(map[string]struct{})
	var ids []string
	for _, r := range rules {
		if r == nil || r.InsightID == "" {
			continue
		}
		if _, dup := seen[r.InsightID]; !dup {
			seen[r.InsightID] = struct{}{}
			ids = append(ids, r.InsightID)
		}
	}
	if len(ids) == 0 {
		return "", 0, false, nil
	}

	sort.Strings(ids)
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = "'" + id + "'"
	}
	return "insights.id:[" + strings.Join(quoted, ", ") + "]", len(ids), true, nil
}

// getInsightDefinitions returns deduplicated, slimmed insight definition entries,
// one per unique insight_id. Multiple rule instances for the same insight_id are
// merged: providers and resource_types are aggregated, controls deduplicated, and
// the name's trailing resource-type suffix stripped. First-seen order is
// preserved for stable output.
func (m *Module) getInsightDefinitions(ctx context.Context) ([]map[string]any, error) {
	rules, err := m.fetchPFMRules(ctx)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return []map[string]any{}, nil
	}

	order := make([]string, 0, len(rules))
	merged := make(map[string]*insightMergeEntry, len(rules))
	for _, rule := range rules {
		if rule == nil || rule.InsightID == "" || rule.Category == "" {
			continue
		}
		e, exists := merged[rule.InsightID]
		if !exists {
			e = &insightMergeEntry{
				insightID:     rule.InsightID,
				category:      rule.Category,
				name:          stripNameSuffix(base.Deref(rule.Name)),
				description:   base.Deref(rule.Description),
				providers:     map[string]struct{}{},
				resourceTypes: map[string]struct{}{},
				controlKeys:   map[string]struct{}{},
			}
			merged[rule.InsightID] = e
			order = append(order, rule.InsightID)
		}
		mergeRuleIntoEntry(e, rule)
	}

	return finalizeDefinitions(order, merged), nil
}

// stripNameSuffix drops the trailing " - <resource type>" qualifier from a rule
// name, splitting on the first separator so the insight name stays intact if a
// resource-type qualifier ever contains a separator of its own.
func stripNameSuffix(raw string) string {
	if before, _, found := strings.Cut(raw, " - "); found {
		return strings.TrimSpace(before)
	}
	return raw
}

// slimControl reduces a raw compliance control to its name, framework, section,
// and requirement.
func slimControl(ctrl *models.ApimodelsControl) map[string]any {
	framework := ""
	if len(ctrl.SecurityFramework) > 0 && ctrl.SecurityFramework[0] != nil {
		framework = base.Deref(ctrl.SecurityFramework[0].Name)
	}
	return map[string]any{
		"name":        base.Deref(ctrl.Name),
		"framework":   framework,
		"section":     ctrl.SectionName,
		"requirement": ctrl.Requirement,
	}
}

// mergeRuleIntoEntry folds one rule's provider, resource types, and controls into
// the accumulating entry, deduplicating controls by (name, framework).
func mergeRuleIntoEntry(e *insightMergeEntry, rule *models.ApimodelsRule) {
	if provider := base.Deref(rule.Provider); provider != "" {
		e.providers[provider] = struct{}{}
	}

	for _, rt := range rule.ResourceTypes {
		if rt == nil {
			continue
		}
		if name := base.Deref(rt.ResourceType); name != "" {
			e.resourceTypes[name] = struct{}{}
		}
	}

	for _, c := range rule.Controls {
		if c == nil {
			continue
		}
		slim := slimControl(c)
		name, _ := slim["name"].(string)
		framework, _ := slim["framework"].(string)
		key := name + "\x00" + framework
		if _, dup := e.controlKeys[key]; !dup {
			e.controlKeys[key] = struct{}{}
			e.controls = append(e.controls, slim)
		}
	}
}

// finalizeDefinitions renders the merged entries into output records in first-seen
// order, sorting the aggregated providers and resource_types and including
// controls only when non-empty.
func finalizeDefinitions(order []string, merged map[string]*insightMergeEntry) []map[string]any {
	defs := make([]map[string]any, 0, len(order))
	for _, id := range order {
		e := merged[id]
		item := map[string]any{
			"insight_id":     e.insightID,
			"category":       e.category,
			"name":           e.name,
			"description":    e.description,
			"providers":      sortedKeys(e.providers),
			"resource_types": sortedKeys(e.resourceTypes),
		}
		if len(e.controls) > 0 {
			item["controls"] = e.controls
		}
		defs = append(defs, item)
	}
	return defs
}

// sortedKeys returns the keys of a set as a sorted slice, never nil.
func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
