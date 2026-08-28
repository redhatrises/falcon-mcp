package cloud

import (
	"context"
	"slices"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

const (
	// insightRulesFilter selects the Policy Framework rules that define cloud
	// insights (the catalog behind the insight tools).
	insightRulesFilter = "rule_domain:'CSPM'+rule_subdomain:'Insight'"

	// pfmQueryPageSize is the page size used while paginating QueryRule for IDs.
	pfmQueryPageSize = 500

	// pfmMaxRules bounds the number of rule IDs accumulated from QueryRule. The
	// live CSPM catalog is a few thousand rules, so this leaves ample headroom
	// while keeping the loop finite if the API ever stops returning a short
	// final page.
	pfmMaxRules = 10000

	// pfmGetBatchSize is the maximum number of rule IDs GetRule accepts per call.
	pfmGetBatchSize = 100

	// pfmRulesCacheTTL is how long a fetchPFMRules result stays fresh in
	// pfmCache. The insight catalog changes rarely, so a short TTL spares the
	// auto-filter and definition-listing paths a full re-fetch (catalog
	// pagination plus batched hydration) on every call.
	pfmRulesCacheTTL = 10 * time.Minute
)

// pfmCacheEntry is a cached fetchPFMRules result and the time it was fetched,
// used to judge freshness against pfmRulesCacheTTL.
type pfmCacheEntry struct {
	fetchedAt time.Time
	rules     []*models.ApimodelsRule
}

// fetchPFMRules returns the Policy Framework insight rules, memoized for
// pfmRulesCacheTTL. A fresh cache hit skips the API entirely; otherwise it
// fetches, caches, and returns the result. Every path returns a shallow copy so
// a caller mutating its slice cannot corrupt the cached entry (or another
// caller's copy); the rule pointers themselves are shared and must be treated
// as read-only.
func (m *Module) fetchPFMRules(ctx context.Context) ([]*models.ApimodelsRule, error) {
	if cached, ok := m.cachedPFMRules(); ok {
		return cached, nil
	}
	rules, err := m.fetchPFMRulesUncached(ctx)
	if err != nil {
		return nil, err
	}
	return m.storePFMRules(rules), nil
}

// cachedPFMRules returns a copy of the cached rules when the entry exists and is
// younger than pfmRulesCacheTTL. The lock covers only the cache read, never an
// API call.
func (m *Module) cachedPFMRules() ([]*models.ApimodelsRule, bool) {
	m.pfmCacheMu.Lock()
	defer m.pfmCacheMu.Unlock()
	if m.pfmCache == nil || time.Since(m.pfmCache.fetchedAt) >= pfmRulesCacheTTL {
		return nil, false
	}
	return slices.Clone(m.pfmCache.rules), true
}

// storePFMRules caches a copy of rules, stamped now, and returns a separate copy
// for the caller. The lock covers only the cache write.
func (m *Module) storePFMRules(rules []*models.ApimodelsRule) []*models.ApimodelsRule {
	m.pfmCacheMu.Lock()
	defer m.pfmCacheMu.Unlock()
	m.pfmCache = &pfmCacheEntry{fetchedAt: time.Now(), rules: slices.Clone(rules)}
	return slices.Clone(rules)
}

// fetchPFMRulesUncached retrieves the Policy Framework insight rules, paginating
// QueryRule for IDs and hydrating them through GetRule in batches.
func (m *Module) fetchPFMRulesUncached(ctx context.Context) ([]*models.ApimodelsRule, error) {
	ids, err := m.queryPFMRuleIDs(ctx)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []*models.ApimodelsRule{}, nil
	}
	return m.getPFMRules(ctx, ids)
}

// queryPFMRuleIDs paginates QueryRule, deduping IDs across pages, until a stop
// condition is met: an empty or short page, a full page with no new IDs (the
// server replaying a page), exact agreement with the reported total, or the
// pfmMaxRules cap.
func (m *Module) queryPFMRuleIDs(ctx context.Context) ([]string, error) {
	var ids []string
	seen := make(map[string]struct{})
	offset := 0
	filter := insightRulesFilter

	for {
		params := cloud_policies.NewQueryRuleParamsWithContext(ctx)
		params.Filter = &filter
		params.Limit = new(int64(pfmQueryPageSize))
		params.Offset = new(int64(offset))

		resp, err := m.Policies.QueryRule(params)
		if e := base.APIError(err, resp, scopePoliciesRead); e != nil {
			return nil, e
		}

		page := resp.Payload.Resources
		if len(page) == 0 {
			break
		}

		newCount := 0
		for _, id := range page {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				ids = append(ids, id)
				newCount++
			}
		}

		// A short page is the last page. Check this before total, so a total
		// that under-reports can never truncate a full page of results.
		if len(page) < pfmQueryPageSize {
			break
		}

		// A full page that contributed nothing new means the server stopped
		// honoring offset and is replaying a page. Progress is judged on new
		// IDs because the dedupe holds len(ids) flat here.
		if newCount == 0 {
			m.Logger.Warn("PFM QueryRule returned a full page with no new rules; stopping to avoid re-requesting the same page",
				"filter", filter, "offset", offset)
			break
		}

		// Exact agreement only. It saves one empty round-trip when total is an
		// exact multiple of the page size. A larger len(ids) means total
		// under-reports (trusting it would drop later pages); a smaller one
		// means a duplicate was deduped and there is more to fetch.
		if total := pfmReportedTotal(resp); total != nil && int64(len(ids)) == *total {
			break
		}

		offset += len(page)

		// Bound on offset, which advances every iteration, rather than on
		// len(ids), which the dedupe can hold flat.
		if offset >= pfmMaxRules {
			m.Logger.Warn("PFM rule pagination hit the rule cap; results are truncated",
				"cap", pfmMaxRules, "filter", filter)
			break
		}
	}

	return ids, nil
}

// getPFMRules hydrates rule IDs into typed rules via GetRule, in batches of
// pfmGetBatchSize (the endpoint's per-request ID limit) fetched concurrently.
// Catalog order is not significant, so no KeyFn is supplied and results are
// returned in fetch order without reordering or deduping.
func (m *Module) getPFMRules(ctx context.Context, ids []string) ([]*models.ApimodelsRule, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.ApimodelsRule]{
		IDs:         ids,
		ChunkSize:   pfmGetBatchSize,
		Concurrency: m.Concurrency,
		Fetch: func(ctx context.Context, chunk []string) ([]*models.ApimodelsRule, error) {
			params := cloud_policies.NewGetRuleParamsWithContext(ctx)
			params.Ids = chunk
			resp, err := m.Policies.GetRule(params)
			if e := base.APIError(err, resp, scopePoliciesRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
	})
}

// pfmReportedTotal reads the total from a QueryRule response's pagination meta,
// returning nil when any level of that nested structure is absent.
func pfmReportedTotal(resp *cloud_policies.QueryRuleOK) *int64 {
	if resp == nil || resp.Payload == nil || resp.Payload.Meta == nil || resp.Payload.Meta.Pagination == nil {
		return nil
	}
	return resp.Payload.Meta.Pagination.Total
}
