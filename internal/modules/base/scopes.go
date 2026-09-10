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

package base

// Scope is an API scope an operation requires, declared by the module that
// calls the operation. Read and Write map to the CrowdStrike console
// permission suffixes ":read" and ":write".
type Scope struct {
	// Name is the console permission name (e.g. "Hosts", "host-group").
	Name string
	// Read grants the ":read" permission for Name.
	Read bool
	// Write grants the ":write" permission for Name.
	Write bool
}

// Strings renders the console permission strings for the scope (e.g.
// {"Hosts:read", "Hosts:write"}). It returns nil when neither Read nor Write
// is set.
func (s Scope) Strings() []string {
	var out []string
	if s.Read {
		out = append(out, s.Name+":read")
	}
	if s.Write {
		out = append(out, s.Name+":write")
	}
	return out
}
