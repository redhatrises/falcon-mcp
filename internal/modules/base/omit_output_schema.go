package base

import (
	"context"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// omitOutputSchemaServers tracks *mcp.Server instances that already have the
// tools/list outputSchema-stripping middleware installed. The go-sdk has no
// "install once" guard on AddReceivingMiddleware, so we de-dupe ourselves.
var omitOutputSchemaServers sync.Map // *mcp.Server -> struct{}

// ensureOmitOutputSchemaFromToolsList installs receiving middleware on s that
// strips OutputSchema from tools/list responses. It is idempotent per server.
//
// Why: the go-sdk's mcp.AddTool always publishes Tool.OutputSchema for typed
// Out (and base.AddTool sets a custom inferred schema for opaque gofalcon
// records). That schema is valuable for call-time StructuredContent validation,
// but advertising it on every tools/list entry reintroduces the client context
// blow-up fixed in Python via structured_output=False (issues #325 / #376).
// Validation still uses the resolved schema captured in the handler closure, so
// clearing the published field does not disable structured results.
func ensureOmitOutputSchemaFromToolsList(s *mcp.Server) {
	if s == nil {
		return
	}
	if _, loaded := omitOutputSchemaServers.LoadOrStore(s, struct{}{}); loaded {
		return
	}
	s.AddReceivingMiddleware(omitOutputSchemaFromToolsList)
}

// omitOutputSchemaFromToolsList is the receiving middleware that redacts
// OutputSchema from tools/list results. It returns shallow copies of each tool
// so the server's stored descriptors (and any concurrent readers) are untouched.
func omitOutputSchemaFromToolsList(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil || method != "tools/list" {
			return res, err
		}
		list, ok := res.(*mcp.ListToolsResult)
		if !ok || list == nil || len(list.Tools) == 0 {
			return res, err
		}
		tools := make([]*mcp.Tool, len(list.Tools))
		for i, t := range list.Tools {
			if t == nil {
				continue
			}
			if t.OutputSchema == nil {
				tools[i] = t
				continue
			}
			cp := *t
			cp.OutputSchema = nil
			tools[i] = &cp
		}
		list.Tools = tools
		return list, nil
	}
}
