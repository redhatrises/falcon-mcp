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
