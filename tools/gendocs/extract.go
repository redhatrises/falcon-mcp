// MIT License
//
// Copyright (c) 2026 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
)

// toolNamePrefix is prepended to every registered tool name, matching
// base.AddTool. Doc pages and the example/note maps use the prefixed name.
const toolNamePrefix = "falcon_"

// moduleDoc assembles the full documentation model for the package from its
// source: identity (key/title/slug/description), tools with their scopes and
// example prompts, resources, and the module-level scope union.
func (p *astPackage) moduleDoc() (moduleDoc, error) {
	key, ok := p.methodReturnString("Name")
	if !ok {
		return moduleDoc{}, fmt.Errorf("no resolvable Name() method")
	}
	description, _ := p.methodReturnString("Description")

	meta := moduleMeta(key)
	doc := moduleDoc{
		Key:         key,
		Title:       meta.title,
		Slug:        meta.slug,
		Description: description,
		Tools:       p.tools(),
		Resources:   p.resources(),
	}
	doc.Scopes = unionScopes(doc.Tools)
	return doc, nil
}

// tools extracts one toolDoc per base.AddTool call reachable from RegisterTools,
// in registration (source) order. Registration may be split across module-local
// helper methods (a module can call m.registerSearchTools(r) from RegisterTools),
// so the walk follows those calls in place. Each tool's scopes are traced from
// its handler method and its example prompts are looked up by prefixed name.
func (p *astPackage) tools() []toolDoc {
	var tools []toolDoc
	p.walkToolRegistration("RegisterTools", map[string]bool{}, func(call *ast.CallExpr, locals map[string]ast.Expr) {
		lit := p.resolveCompositeLit(call.Args[1], locals)
		if lit == nil {
			return
		}
		rawName, ok := p.evalString(fieldValue(lit, "Name"))
		if !ok {
			return
		}
		name := toolNamePrefix + rawName
		desc, _ := p.evalString(fieldValue(lit, "Description"))

		tools = append(tools, toolDoc{
			Name:        name,
			Description: desc,
			Annotation:  annotationOf(fieldValue(lit, "Annotations")),
			Scopes:      p.handlerScopes(handlerName(call.Args[2])),
			Examples:    toolExamples[name],
		})
	})
	return tools
}

// walkToolRegistration visits, in source order, every base.AddTool call reachable
// from the named function, descending into module-local registration helpers it
// calls. emit receives each AddTool call together with the local variable
// assignments of the function it appears in, so a tool built into a local before
// registration resolves. The seen set guards against a helper cycle.
func (p *astPackage) walkToolRegistration(fn string, seen map[string]bool, emit func(*ast.CallExpr, map[string]ast.Expr)) {
	if seen[fn] {
		return
	}
	seen[fn] = true

	for _, fd := range p.funcs[fn] {
		if fd.Body == nil {
			continue
		}
		locals := localAssignments(fd.Body)

		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if isBaseCall(call.Fun, "AddTool") && len(call.Args) >= 3 {
				emit(call, locals)
				return false
			}
			if callee := calleeName(call.Fun); callee != "" {
				if len(p.funcs[callee]) > 0 {
					p.walkToolRegistration(callee, seen, emit)
					return false
				}
			}
			return true
		})
	}
}

// localAssignments records the single-identifier assignments in a function body,
// mapping each name to its assigned expression. It lets tools() resolve a tool
// built into a local variable (searchTool := &mcp.Tool{...}) before being passed
// to base.AddTool.
func localAssignments(body *ast.BlockStmt) map[string]ast.Expr {
	locals := map[string]ast.Expr{}
	for _, stmt := range body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok {
			if _, seen := locals[id.Name]; !seen {
				locals[id.Name] = assign.Rhs[0]
			}
		}
	}
	return locals
}

// resources extracts one resourceDoc per base.TextResource call in
// RegisterResources, in source order. The URI is the second argument and the
// description the fourth (base.TextResource(s, uri, name, description, mime, text)).
func (p *astPackage) resources() []resourceDoc {
	var resources []resourceDoc
	for _, fd := range p.funcs["RegisterResources"] {
		if fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isBaseCall(call.Fun, "TextResource") || len(call.Args) < 4 {
				return true
			}
			uri, ok := p.evalString(call.Args[1])
			if !ok {
				return true
			}
			desc, _ := p.evalString(call.Args[3])
			resources = append(resources, resourceDoc{URI: uri, Description: desc})
			return true
		})
	}
	return resources
}

// handlerScopes traces the scopes a tool requires by walking its handler method
// and, transitively, the module-local methods and functions it calls, collecting
// every reference to a package-level scope variable. Following the call chain
// matters because a tool may reach the API through a helper (a discriminator's
// readScope/writeScope, a shared fetch) or through another tool method, and the
// scope is referenced only there. The traversal is breadth-first and guards
// against cycles.
func (p *astPackage) handlerScopes(handler string) []string {
	if handler == "" {
		return nil
	}

	found := map[string]bool{}
	seen := map[string]bool{}
	queue := []string{handler}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true

		for _, fd := range p.funcs[name] {
			if fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.Ident:
					if s, ok := p.scopeVars[node.Name]; ok {
						for _, str := range s.strings() {
							found[str] = true
						}
					}
				case *ast.CallExpr:
					if callee := calleeName(node.Fun); callee != "" {
						if len(p.funcs[callee]) > 0 {
							queue = append(queue, callee)
						}
					}
				}
				return true
			})
		}
	}

	return sortScopes(found)
}

// calleeName reports the identifier a call targets when it is a bare function
// call (helper(...)) or a selector call whose selector names a module-local
// method (m.helper(...)). It returns "" for calls the tracer should not follow,
// such as base.* and gofalcon client calls.
func calleeName(fun ast.Expr) string {
	switch f := unwrapIndex(fun).(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		// A selector may name a module-local method (m.helper). The caller
		// confirms the name is a known function before enqueuing, so returning
		// the selector name is safe even for non-local selectors like base.X.
		return f.Sel.Name
	}
	return ""
}

// handlerName reports the method name of an AddTool handler argument, e.g.
// m.searchDetections yields "searchDetections".
func handlerName(arg ast.Expr) string {
	if sel, ok := arg.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	if id, ok := arg.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// annotationOf classifies a tool from its Annotations field expression: a
// base.MutatingAnnotations(...) call marks a non-destructive mutator, a
// base.DestructiveAnnotations(...) call marks a destructive one, and anything
// else (including an absent field) is read-only.
func annotationOf(expr ast.Expr) annotationKind {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return annotationReadOnly
	}
	switch {
	case isBaseCall(call.Fun, "DestructiveAnnotations"):
		return annotationDestructive
	case isBaseCall(call.Fun, "MutatingAnnotations"):
		return annotationMutating
	}
	return annotationReadOnly
}

// resolveCompositeLit returns the struct composite literal an expression
// ultimately denotes, following a leading address-of (&mcp.Tool{...}), a
// function-local variable, or a package-level variable. It returns nil when the
// expression does not resolve to a composite literal. The bounded loop guards
// against a reference cycle.
func (p *astPackage) resolveCompositeLit(expr ast.Expr, locals map[string]ast.Expr) *ast.CompositeLit {
	for range 100 {
		switch e := expr.(type) {
		case *ast.UnaryExpr:
			expr = e.X
		case *ast.CompositeLit:
			return e
		case *ast.Ident:
			if v, ok := locals[e.Name]; ok {
				expr = v
				continue
			}
			if v, ok := p.values[e.Name]; ok {
				expr = v
				continue
			}
			return nil
		default:
			return nil
		}
	}
	return nil
}

// fieldValue returns the value of the named field in a struct composite literal,
// or nil when the field is absent.
func fieldValue(lit *ast.CompositeLit, field string) ast.Expr {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok && key.Name == field {
			return kv.Value
		}
	}
	return nil
}

// unionScopes collects the distinct scopes across every tool, sorted.
func unionScopes(tools []toolDoc) []string {
	set := map[string]bool{}
	for _, t := range tools {
		for _, s := range t.Scopes {
			set[s] = true
		}
	}
	return sortScopes(set)
}

// sortScopes returns the set's members ordered read-before-write, then
// alphabetically — matching the order the retired Python generator emitted.
func sortScopes(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		iWrite := strings.HasSuffix(out[i], ":write")
		jWrite := strings.HasSuffix(out[j], ":write")
		if iWrite != jWrite {
			return !iWrite
		}
		return out[i] < out[j]
	})
	return out
}
