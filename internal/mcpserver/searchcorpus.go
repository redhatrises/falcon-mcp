package mcpserver

import (
	"regexp"
	"sort"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// toolNamePrefix is the prefix base.AddTool applies to every tool name. The
// catalog keys tools by their prefixed name; lookup also accepts the bare name.
const toolNamePrefix = "falcon_"

// nonAlnum splits identifiers and queries on runs of non-alphanumeric
// characters, so "search-hosts" and "search_hosts" tokenize identically.
var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// Relative ranking weights. The gap between tiers exceeds the token count any
// realistic query carries, so a name-word match outranks any number of
// description matches; a token that hits nothing scores nothing.
const (
	scoreExactName       = 1000
	scoreNameWord        = 10
	scoreNameSubstring   = 5
	scoreModuleWord      = 3
	scoreModuleSubstring = 2
	scoreDescription     = 1
)

// tierRescueBelow is how many full-coverage matches make a result page an answer on
// its own. Below it, the partial block is admitted to rescue a right answer the
// conjunction excluded; at or above it a precise query never pays for the wider set.
const tierRescueBelow = 3

// stopwords carry intent but not identity: generic verbs, determiners, and
// conversational filler. They are dropped before the every-token conjunction and
// score nothing outside a tool's own name, because they reach most of the corpus as
// prose ("returns an empty list") and so decide nothing about which tool is wanted.
// Words that identify an entity or an operation kind stay out — "count", "aggregate",
// "members", "details", "full" all genuinely narrow. "falcon" and "return"/"returns"
// are here because they reach very nearly every entry: the corpus is built from the
// prefixed tool name, and almost every description has a "Returns" line.
var stopwords = words(
	"a an the of for to in on at and or from with by is are was were be been am " +
		"i me my we our us you your it its this that these those there " +
		"do does did done can could would should will shall may might must " +
		"what which who whom whose when where why how " +
		"show list get find search see look tell give fetch return returns retrieve display " +
		"all any some every each single both many much more most " +
		"please thanks thank hey hi ok okay just really actually now right currently " +
		"need needs want wants know knows help helps figure out way best able " +
		"have has had having falcon")

// words splits text into the set of its lowercase alphanumeric words.
func words(text string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, w := range nonAlnum.Split(strings.ToLower(text), -1) {
		if w != "" {
			out[w] = struct{}{}
		}
	}
	return out
}

// wordsList returns the deduped lowercase alphanumeric words of text in order,
// for iterating query tokens.
func wordsList(text string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, w := range nonAlnum.Split(strings.ToLower(text), -1) {
		if w == "" {
			continue
		}
		if _, dup := seen[w]; dup {
			continue
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	return out
}

// normalizeIdentifier reduces a name to lowercase alphanumerics, dropping
// separators, so "Host_Groups", "host-groups", and "hostgroups" share a key.
func normalizeIdentifier(name string) string {
	return nonAlnum.ReplaceAllString(strings.ToLower(name), "")
}

// containsAll reports whether corpus contains every token as a substring.
func containsAll(corpus string, tokens []string) bool {
	for _, t := range tokens {
		if !strings.Contains(corpus, t) {
			return false
		}
	}
	return true
}

// containsAny reports whether corpus contains at least one token as a substring.
func containsAny(corpus string, tokens []string) bool {
	for _, t := range tokens {
		if strings.Contains(corpus, t) {
			return true
		}
	}
	return false
}

// paramSummary describes one tool parameter for search results. It mirrors
// upstream falcon-mcp's per-parameter summary: type, whether it is required,
// its description, and any examples. Examples are populated only for the
// full-schema path (falcon_search_tools with tool_names); the lean discovery
// path omits the whole parameter list, so it never carries examples, matching
// upstream's summarize_parameters vs _format_entry split.
type paramSummary struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Required    bool   `json:"required"`
	Description string `json:"description,omitempty"`
	Examples    []any  `json:"examples,omitempty"`
}

// paramSummaries extracts the top-level parameters from a tool's inferred input
// schema (the *jsonschema.Schema base.AddTool derives from the handler's In
// type). It reflects exactly the schema the served tool advertises and, unlike
// raw struct reflection, omits json:"-" fields. Parameters are returned in
// sorted name order for deterministic output. A nil schema (In is any) yields
// no parameters.
func paramSummaries(schema *jsonschema.Schema) []paramSummary {
	if schema == nil || len(schema.Properties) == 0 {
		return nil
	}
	required := make(map[string]bool, len(schema.Required))
	for _, name := range schema.Required {
		required[name] = true
	}

	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]paramSummary, 0, len(names))
	for _, name := range names {
		p := schema.Properties[name]
		summary := paramSummary{Name: name, Required: required[name]}
		if p != nil {
			summary.Type = p.Type
			summary.Description = p.Description
			if len(p.Examples) > 0 {
				summary.Examples = p.Examples
			}
		}
		out = append(out, summary)
	}
	return out
}

// searchCorpus builds the lowercased text falcon_search_tools matches against,
// mirroring upstream's "{name} {description} {module} {param_names}".
func searchCorpus(tool *mcp.Tool, module string, params []paramSummary) string {
	var b strings.Builder
	b.WriteString(tool.Name)
	b.WriteByte(' ')
	b.WriteString(tool.Description)
	b.WriteByte(' ')
	b.WriteString(module)
	for _, p := range params {
		b.WriteByte(' ')
		b.WriteString(p.Name)
	}
	return strings.ToLower(b.String())
}

// deriveRanking populates the fields score reads — the name and module word
// sets and normalized keys — from the entry's tool name and module. It is
// called once at registration so search does not re-tokenize on every query.
func (ce *catalogEntry) deriveRanking() {
	name := strings.ToLower(ce.tool.Name)
	ce.unprefixedName = strings.TrimPrefix(name, toolNamePrefix)
	ce.nameWords = words(ce.unprefixedName)
	// Both spellings are an exact hit, so a query can name the tool with or
	// without the server's prefix.
	ce.nameKey = map[string]struct{}{
		normalizeIdentifier(name):              {},
		normalizeIdentifier(ce.unprefixedName): {},
	}
	ce.moduleWords = words(ce.module)
	ce.moduleKey = normalizeIdentifier(ce.module)
}

// score ranks ce against a tokenized query; higher sorts earlier. It returns
// (matched, strength): matched is how many query tokens hit any field — the
// primary key, so a tool covering more of the query outranks one covering less
// wherever the hits land. strength is the weighted sum within that coverage,
// each token scored once at the strongest field it hits, so a tool named for
// the query outranks one that only mentions it in prose. queryKey is the whole
// normalized query, matched against the name key for the exact-name
// short-circuit. A token that hits nothing adds to neither total, and a generic
// token (stopwords) counts only where it hits this tool's own name.
func (ce catalogEntry) score(tokens []string, queryKey string) (matched, strength int) {
	if queryKey != "" {
		if _, ok := ce.nameKey[queryKey]; ok {
			return len(tokens) + 1, scoreExactName
		}
	}
	for _, token := range tokens {
		switch {
		case setHas(ce.nameWords, token):
			strength += scoreNameWord
		case strings.Contains(ce.unprefixedName, token):
			strength += scoreNameSubstring
		case setHas(stopwords, token):
			// A generic word reaches most descriptions as prose, so crediting it
			// outside a tool's own name measures docstring wording rather than
			// relevance — enough to let a mutator outrank its read-only sibling.
			continue
		case setHas(ce.moduleWords, token):
			strength += scoreModuleWord
		case strings.Contains(ce.moduleKey, token):
			strength += scoreModuleSubstring
		case strings.Contains(ce.corpus, token):
			strength += scoreDescription
		default:
			continue
		}
		matched++
	}
	return matched, strength
}

// namesAny reports whether any token hits this entry's own name — the two name
// tiers score() rewards, asked as a yes/no. Candidate selection counts corpus hits
// without regard to where they land, which lets a tool matching several words only
// in prose qualify while a sibling named for the query misses the count; the score
// already treats a name hit as worth many prose hits, and this keeps selection
// consistent with that.
func (ce catalogEntry) namesAny(tokens []string) bool {
	for _, t := range tokens {
		if setHas(ce.nameWords, t) || strings.Contains(ce.unprefixedName, t) {
			return true
		}
	}
	return false
}

// setHas reports membership in a string set.
func setHas(s map[string]struct{}, k string) bool {
	_, ok := s[k]
	return ok
}
