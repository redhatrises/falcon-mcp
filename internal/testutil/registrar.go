package testutil

import "github.com/crowdstrike/falcon-mcp/internal/modules/base"

// CaptureRegistrar is a base.Registrar that forwards each registered
// base.ToolEntry to the wrapped function, letting tests capture the tools a
// module registers.
type CaptureRegistrar func(base.ToolEntry)

// Add forwards e to the wrapped function, satisfying base.Registrar.
func (f CaptureRegistrar) Add(e base.ToolEntry) { f(e) }
