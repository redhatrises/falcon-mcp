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

package discover

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_applications.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_hosts.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_managed_hosts.md

// MCP resource URIs for the discover FQL guides, matching falcon-mcp's
// falcon://discover/applications/fql-guide, falcon://discover/hosts/fql-guide,
// and falcon://discover/managed-assets/fql-guide resources.
const (
	applicationsFQLGuideURI    = "falcon://discover/applications/fql-guide"
	unmanagedAssetsFQLGuideURI = "falcon://discover/hosts/fql-guide"
	managedAssetsFQLGuideURI   = "falcon://discover/managed-assets/fql-guide"
)

// applicationsFQLGuide is the FQL documentation for searching applications. It
// is served as the search_applications FQL guide resource and returned inline
// inside FQL-error responses. Whitespace in fql_guide_applications.md is
// normalized by `go generate` (see the directives above).
//
//go:embed fql_guide_applications.md
var applicationsFQLGuide string

// unmanagedAssetsFQLGuide is the FQL documentation for searching unmanaged
// assets. It is served as the search_unmanaged_assets FQL guide resource and
// returned inline inside FQL-error responses.
//
//go:embed fql_guide_hosts.md
var unmanagedAssetsFQLGuide string

// managedAssetsFQLGuide is the FQL documentation for searching managed assets.
// It is served as the search_managed_assets FQL guide resource and returned
// inline inside FQL-error responses.
//
//go:embed fql_guide_managed_hosts.md
var managedAssetsFQLGuide string
