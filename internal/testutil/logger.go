// Package testutil provides shared helpers for the falcon-mcp unit tests:
// a discard logger, MCP tool-annotation assertions, an in-memory MCP client
// session, and a capturing tool registrar. It is imported only by _test.go
// files and is never linked into the production binary.
package testutil

import "log/slog"

// DiscardLogger returns a logger that discards all output. Modules require a
// non-nil logger, so tests pass this when the log output itself is not under
// test.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
