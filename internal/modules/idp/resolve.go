package idp

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// sanitizeInputPattern removes characters that could break out of a GraphQL
// string literal, mirroring the Python common.utils.sanitize_input: it strips
// backslashes, quotes, and control whitespace, then caps length at 255.
var sanitizeInputPattern = regexp.MustCompile(`[\\"'\n\r\t]`)

// sanitizeInput strips injection-prone characters and caps length, mirroring the
// Python sanitize_input used before embedding identifiers into GraphQL filters.
// The 255 cap is applied by rune count (not bytes) so a multi-byte UTF-8
// character near the boundary is never split, matching Python's codepoint-based
// slicing.
func sanitizeInput(s string) string {
	sanitized := sanitizeInputPattern.ReplaceAllString(s, "")
	if r := []rune(sanitized); len(r) > 255 {
		sanitized = string(r[:255])
	}
	return sanitized
}

// resolveEntities resolves entity IDs from the supplied identifiers using a
// single unified AND-based GraphQL query, mirroring the Python _resolve_entities.
// Direct entity IDs need no resolution and are included as-is. Email (USER) and
// IP (ENDPOINT) criteria cannot be combined in one query; when both are present,
// USER takes precedence and the IP criterion is dropped.
//
// It returns (ids, nil) on success or (nil, apiErr) on a GraphQL API failure.
// The returned IDs are deduplicated in first-seen order (direct IDs first, then
// resolved), which the Python code does not guarantee (it uses set()) but is a
// harmless, more predictable superset of that behavior.
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

	// Direct entity IDs need no resolution.
	for _, id := range c.EntityIDs {
		add(id)
	}

	hasUserCriteria := c.EmailAddresses != ""
	hasEndpointCriteria := len(c.IPAddresses) > 0
	ipAddresses := c.IPAddresses

	// USER (email) and ENDPOINT (IP) criteria conflict in a single query; prefer
	// USER, dropping the IP criterion, mirroring the Python resolution.
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
	// Add account information for domain context, mirroring the Python append.
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

// sanitizeList applies sanitizeInput to each element, mirroring the Python
// [sanitize_input(x) for x in list].
func sanitizeList(items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = sanitizeInput(s)
	}
	return out
}

// joinFields renders the deduplicated field set as newline-joined selections.
// The Python code deduplicates via set() (unordered); to keep the generated
// query stable across runs the fields are sorted here, which does not affect the
// GraphQL result.
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
