package idp

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// sanitizeInputPattern matches characters that could break out of a GraphQL
// string literal: backslashes, quotes, and control whitespace.
var sanitizeInputPattern = regexp.MustCompile(`[\\"'\n\r\t]`)

// sanitizeInput strips injection-prone characters and caps length at 255, and is
// applied to every caller-supplied identifier before it reaches a query builder.
// The cap is applied by rune count (not bytes) so a multi-byte UTF-8 character
// near the boundary is never split.
func sanitizeInput(s string) string {
	sanitized := sanitizeInputPattern.ReplaceAllString(s, "")
	if r := []rune(sanitized); len(r) > 255 {
		sanitized = string(r[:255])
	}
	return sanitized
}

// resolveEntities resolves entity IDs from the supplied identifiers using a
// single unified AND-based GraphQL query. Email (USER) and IP (ENDPOINT) criteria
// cannot be combined in one query; when both are present, USER takes precedence
// and the IP criterion is dropped.
//
// It returns (ids, nil) on success or (nil, apiErr) on a GraphQL API failure.
// The returned IDs are deduplicated in first-seen order (direct IDs first, then
// resolved).
func (m *Module) resolveEntities(ctx context.Context, c SearchCriteria, limit int) ([]string, *base.Error) {
	resolved := map[string]struct{}{}
	var order []string
	add := func(id string) {
		if id == "" {
			return
		}
		if _, ok := resolved[id]; !ok {
			resolved[id] = struct{}{}
			order = append(order, id)
		}
	}

	// Direct entity IDs need no resolution, but they are caller-supplied and so
	// are sanitized like every other identifier: the builders that embed them
	// encode at the point of use, and sanitizing here keeps that invariant from
	// depending on a future builder remembering to. It also applies the 255-rune
	// cap, bounding the query text a caller can make the builders assemble.
	for _, id := range c.EntityIDs {
		add(sanitizeInput(id))
	}

	hasUserCriteria := c.EmailAddresses != ""
	hasEndpointCriteria := len(c.IPAddresses) > 0
	ipAddresses := c.IPAddresses

	// USER (email) and ENDPOINT (IP) criteria conflict in a single query; prefer
	// USER, dropping the IP criterion.
	if hasUserCriteria && hasEndpointCriteria {
		m.Logger.Warn("Cannot combine email addresses (USER) and IP addresses (ENDPOINT) in single query. Prioritizing USER entities.")
		ipAddresses = nil
	}

	var queryFilters []string
	fieldSet := map[string]struct{}{}
	addField := func(f string) { fieldSet[f] = struct{}{} }

	// entity_names -> primaryDisplayNamePattern
	if c.EntityNames != "" {
		queryFilters = append(queryFilters, fmt.Sprintf("primaryDisplayNamePattern: %s", jsonString(sanitizeInput(c.EntityNames))))
		addField("primaryDisplayName")
	}
	// email_addresses (USER) -> secondaryDisplayNamePattern + types: [USER]
	if c.EmailAddresses != "" {
		queryFilters = append(queryFilters, fmt.Sprintf("secondaryDisplayNamePattern: %s", jsonString(sanitizeInput(c.EmailAddresses))))
		queryFilters = append(queryFilters, "types: [USER]")
		addField("primaryDisplayName")
		addField("secondaryDisplayName")
	}
	// ip_addresses (ENDPOINT) -> primaryDisplayNames + types: [ENDPOINT]
	if len(ipAddresses) > 0 && !hasUserCriteria {
		queryFilters = append(queryFilters, fmt.Sprintf("primaryDisplayNames: %s", jsonList(sanitizeList(ipAddresses))))
		queryFilters = append(queryFilters, "types: [ENDPOINT]")
		addField("primaryDisplayName")
	}
	// domain_names -> domains
	if len(c.DomainNames) > 0 {
		queryFilters = append(queryFilters, fmt.Sprintf("domains: %s", jsonList(sanitizeList(c.DomainNames))))
		addField("primaryDisplayName")
		addField("secondaryDisplayName")
	}

	// When only direct entity IDs were supplied, there is no query to run.
	if len(queryFilters) == 0 {
		return order, nil
	}

	fieldsString := joinFields(fieldSet)
	// Add account information for domain context.
	if len(c.DomainNames) > 0 {
		fieldsString += `
                    accounts {
                        ... on ActiveDirectoryAccountDescriptor {
                            domain
                            samAccountName
                        }
                    }`
	}

	filtersString := strings.Join(queryFilters, ", ")
	query := fmt.Sprintf(`
            query {
                entities(%s, first: %d) {
                    nodes {
                        entityId
                        %s
                    }
                }
            }
            `, filtersString, limit, fieldsString)

	data, apiErr := m.runGraphQL(ctx, query)
	if apiErr != nil {
		return nil, apiErr
	}

	for _, node := range entityNodes(data) {
		if id, ok := node["entityId"].(string); ok {
			add(id)
		}
	}

	return order, nil
}

// sanitizeList applies sanitizeInput to each element.
func sanitizeList(items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = sanitizeInput(s)
	}
	return out
}

// joinFields renders the deduplicated field set as newline-joined selections.
// The fields are sorted so the generated query is stable across runs, which does
// not affect the GraphQL result.
func joinFields(set map[string]struct{}) string {
	fields := make([]string, 0, len(set))
	for f := range set {
		fields = append(fields, f)
	}
	// Stable order for deterministic queries; sort is cheap for a handful of fields.
	sortStrings(fields)
	return strings.Join(fields, "\n")
}

// sortStrings sorts s in place (small helper to avoid importing sort at each use).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
