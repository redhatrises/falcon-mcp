package mcpserver

import (
	"context"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// orderRecorder wraps a base.Registrar and records the falcon_-prefixed name of
// every tool registered through it, in registration order. registerModules
// registers core tools first, then each enabled module's tools in
// moduleFactories() order, each module's tools in their own registration order,
// so the recorded slice is exactly the order clients should see in tools/list.
type orderRecorder struct {
	inner base.Registrar
	order *[]string
}

func (r orderRecorder) Add(e base.ToolEntry) {
	*r.order = append(*r.order, e.Tool.Name)
	r.inner.Add(e)
}

// orderToolsMiddleware returns a receiving middleware that reorders the tools in
// a tools/list result to match order (the registration order captured by
// orderRecorder). The go-sdk stores tools in a name-sorted map, so its wire
// output is alphabetized regardless of insertion order; this restores the
// Python server's core-first, module-grouped ordering.
//
// It only reorders a complete single page (NextCursor == ""); a paginated
// stream is left untouched so cursor coordination is never disturbed. The
// default PageSize is 1000 and the server registers ~100 tools, so tools/list
// returns a single page in practice.
func orderToolsMiddleware(order []string) mcp.Middleware {
	index := make(map[string]int, len(order))
	for i, name := range order {
		index[name] = i
	}
	rank := func(name string) int {
		if i, ok := index[name]; ok {
			return i
		}
		// Unknown names (should not happen) sort to the end, preserving the
		// SDK's order among themselves via the stable sort.
		return len(order)
	}

	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil || method != "tools/list" {
				return res, err
			}
			list, ok := res.(*mcp.ListToolsResult)
			if !ok || list.NextCursor != "" {
				return res, err
			}
			slices.SortStableFunc(list.Tools, func(a, b *mcp.Tool) int {
				return rank(a.Name) - rank(b.Name)
			})
			return list, nil
		}
	}
}
