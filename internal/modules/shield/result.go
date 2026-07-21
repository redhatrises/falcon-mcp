package shield

import "github.com/crowdstrike/falcon-mcp/internal/modules/base"

// foundOrGuided builds the search-tool result envelope. On a non-empty result
// it returns the records with the API meta attached. On an empty result it
// still returns a valid (empty) result but attaches the query guide and a hint,
// mirroring the Python module's _format_empty_or_error: Shield query APIs return
// HTTP 200 with zero resources for unsupported filters, so an empty set most
// often means the caller's parameters need review.
func foundOrGuided[T any](resources []T, meta any) base.SearchResult[T] {
	if len(resources) == 0 {
		return base.SearchResult[T]{
			Resources: []T{},
			FQLGuide:  queryGuide,
			Hint:      "No results matched your query. Review available parameters in the query guide.",
		}.WithMeta(meta)
	}
	return base.Found(resources, "").WithMeta(meta)
}
