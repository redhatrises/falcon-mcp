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
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// astPackage is a merged, source-level view of one module's Go package: every
// top-level function and method keyed by name, and every package-level const/var
// initializer keyed by identifier. It supports resolving the string and
// base.Scope values the documentation needs without compiling or importing the
// package.
type astPackage struct {
	dir       string
	funcs     map[string][]*ast.FuncDecl // keyed by function/method name; a name may map to several decls (same method on different receiver types)
	values    map[string]ast.Expr
	scopeVars map[string]scope // package-level idents bound to a base.Scope literal
}

// scope mirrors base.Scope for the purpose of rendering console permission
// strings. Name is the console permission (e.g. "Alerts"); Read and Write map to
// the ":read" and ":write" suffixes.
type scope struct {
	Name  string
	Read  bool
	Write bool
}

// strings renders the console permission strings for the scope, e.g.
// {"Alerts:read", "Alerts:write"}.
func (s scope) strings() []string {
	var out []string
	if s.Read {
		out = append(out, s.Name+":read")
	}
	if s.Write {
		out = append(out, s.Name+":write")
	}
	return out
}

// parsePackage parses every non-test Go file in dir (sorted by name for
// determinism) into a single astPackage. When a name is declared more than once
// across files the earliest declaration wins, matching the order Go itself
// resolves package-level identifiers.
func parsePackage(dir string) (*astPackage, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	pkg := &astPackage{dir: dir, funcs: map[string][]*ast.FuncDecl{}, values: map[string]ast.Expr{}}
	fset := token.NewFileSet()
	for _, name := range names {
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		pkg.collect(file)
	}
	pkg.buildScopeVars()
	return pkg, nil
}

// buildScopeVars records every package-level identifier bound to a base.Scope
// composite literal, so a scope can be resolved from a reference anywhere in a
// handler's call chain regardless of whether it is passed to base.APIError
// directly or returned by a discriminator helper.
func (p *astPackage) buildScopeVars() {
	p.scopeVars = map[string]scope{}
	for name, expr := range p.values {
		if s, ok := p.evalScope(expr); ok {
			p.scopeVars[name] = s
		}
	}
}

// collect records the top-level functions and const/var initializers declared in
// file.
func (p *astPackage) collect(file *ast.File) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			// Append rather than first-wins: a package may declare the same
			// method name on several receiver types (e.g. the per-type backends
			// in exclusions/policies). Keeping every declaration lets the scope
			// tracer union across all implementations a call could dispatch to,
			// since the receiver type is not resolvable from the AST alone.
			p.funcs[d.Name.Name] = append(p.funcs[d.Name.Name], d)
		case *ast.GenDecl:
			if d.Tok != token.VAR && d.Tok != token.CONST {
				continue
			}
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						if _, ok := p.values[name.Name]; !ok {
							p.values[name.Name] = vs.Values[i]
						}
					}
				}
			}
		}
	}
}

// evalString resolves expr to a string, following string literals, "+"
// concatenations, parentheses, and package-level const/var references. It
// reports false when expr is not a statically resolvable string.
func (p *astPackage) evalString(expr ast.Expr) (string, bool) {
	return p.evalStringSeen(expr, map[string]bool{})
}

// evalStringSeen is evalString with a cycle guard over the identifiers already
// being resolved, so a self- or mutually-referential const cannot recurse
// forever.
func (p *astPackage) evalStringSeen(expr ast.Expr, seen map[string]bool) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			s, err := strconv.Unquote(e.Value)
			return s, err == nil
		}
	case *ast.ParenExpr:
		return p.evalStringSeen(e.X, seen)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			l, okL := p.evalStringSeen(e.X, seen)
			r, okR := p.evalStringSeen(e.Y, seen)
			return l + r, okL && okR
		}
	case *ast.Ident:
		if seen[e.Name] {
			return "", false
		}
		if v, ok := p.values[e.Name]; ok {
			seen[e.Name] = true
			s, ok := p.evalStringSeen(v, seen)
			// Backtrack so the guard follows the current resolution path only;
			// the same const may legitimately appear in a sibling operand.
			delete(seen, e.Name)
			return s, ok
		}
	}
	return "", false
}

// evalScope resolves expr to a scope. expr is either a base.Scope composite
// literal or an identifier bound to one. It reports false when expr is not a
// resolvable scope.
func (p *astPackage) evalScope(expr ast.Expr) (scope, bool) {
	if id, ok := expr.(*ast.Ident); ok {
		v, ok := p.values[id.Name]
		if !ok {
			return scope{}, false
		}
		expr = v
	}
	cl, ok := expr.(*ast.CompositeLit)
	if !ok || !isScopeType(cl.Type) {
		return scope{}, false
	}

	var s scope
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Name":
			s.Name, _ = p.evalString(kv.Value)
		case "Read":
			s.Read = isTrue(kv.Value)
		case "Write":
			s.Write = isTrue(kv.Value)
		}
	}
	return s, s.Name != ""
}

// methodReturnString resolves the single string a zero-argument method returns
// (e.g. Name or Description), following const references.
func (p *astPackage) methodReturnString(method string) (string, bool) {
	for _, fd := range p.funcs[method] {
		if fd.Body == nil {
			continue
		}
		for _, stmt := range fd.Body.List {
			if ret, ok := stmt.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
				if s, ok := p.evalString(ret.Results[0]); ok {
					return s, true
				}
			}
		}
	}
	return "", false
}

// isBaseCall reports whether fun is a call of the form base.<name>, unwrapping
// any generic type-argument indexing (base.AddTool[...]).
func isBaseCall(fun ast.Expr, name string) bool {
	sel, ok := unwrapIndex(fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "base"
}

// unwrapIndex strips a generic instantiation (IndexExpr / IndexListExpr) to the
// underlying function expression, so base.AddTool[In, Out] resolves like
// base.AddTool.
func unwrapIndex(expr ast.Expr) ast.Expr {
	switch e := expr.(type) {
	case *ast.IndexExpr:
		return e.X
	case *ast.IndexListExpr:
		return e.X
	}
	return expr
}

// isScopeType reports whether t is the type expression base.Scope, so a
// composite literal of another struct that happens to carry a Name field is not
// misread as a scope.
func isScopeType(t ast.Expr) bool {
	sel, ok := t.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Scope" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "base"
}

// isTrue reports whether expr is the boolean literal true.
func isTrue(expr ast.Expr) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "true"
}
