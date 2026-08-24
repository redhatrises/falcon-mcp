package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	gofalconhosts "github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/client/serverless_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	hostgroups "github.com/crowdstrike/falcon-mcp/internal/modules/host_groups"
	hostsmod "github.com/crowdstrike/falcon-mcp/internal/modules/hosts"
	"github.com/crowdstrike/falcon-mcp/internal/modules/serverless"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

// stubHosts and stubGroups are no-op fakes sufficient to register the tools and
// drive tools/list, resources/list, and a read-only tools/call end-to-end.
type stubHosts struct{}

// stubQueryMeta is the response meta stubHosts reports, carrying the fields a
// client acts on so the end-to-end tests can assert the trimmed meta shape.
var stubQueryMeta = &models.MsaMetaInfo{
	Pagination: &models.MsaPaging{Total: new(int64(120)), Limit: new(int32(50)), Offset: new(int32(10))},
	QueryTime:  new(0.02),
	TraceID:    new("trace-conformance"),
	PoweredBy:  "crowdstrike-api",
}

func (stubHosts) QueryDevicesByFilter(*gofalconhosts.QueryDevicesByFilterParams, ...gofalconhosts.ClientOption) (*gofalconhosts.QueryDevicesByFilterOK, error) {
	return &gofalconhosts.QueryDevicesByFilterOK{Payload: &models.MsaQueryResponse{Resources: []string{}, Meta: stubQueryMeta}}, nil
}
func (stubHosts) PostDeviceDetailsV2(*gofalconhosts.PostDeviceDetailsV2Params, ...gofalconhosts.ClientOption) (*gofalconhosts.PostDeviceDetailsV2OK, error) {
	return &gofalconhosts.PostDeviceDetailsV2OK{Payload: &models.DeviceapiDeviceDetailsResponseSwagger{}}, nil
}
func (stubHosts) UpdateDeviceTags(*gofalconhosts.UpdateDeviceTagsParams, ...gofalconhosts.ClientOption) (*gofalconhosts.UpdateDeviceTagsOK, *gofalconhosts.UpdateDeviceTagsAccepted, error) {
	return &gofalconhosts.UpdateDeviceTagsOK{Payload: &models.DeviceapiUpdateDeviceTagsSwaggerV1{}}, nil, nil
}

type stubGroups struct{}

func (stubGroups) QueryCombinedHostGroups(*host_group.QueryCombinedHostGroupsParams, ...host_group.ClientOption) (*host_group.QueryCombinedHostGroupsOK, error) {
	return &host_group.QueryCombinedHostGroupsOK{Payload: &models.HostGroupsRespV1{}}, nil
}
func (stubGroups) QueryCombinedGroupMembers(*host_group.QueryCombinedGroupMembersParams, ...host_group.ClientOption) (*host_group.QueryCombinedGroupMembersOK, error) {
	return &host_group.QueryCombinedGroupMembersOK{Payload: &models.HostGroupsMembersRespV1{}}, nil
}
func (stubGroups) CreateHostGroups(*host_group.CreateHostGroupsParams, ...host_group.ClientOption) (*host_group.CreateHostGroupsCreated, error) {
	return &host_group.CreateHostGroupsCreated{Payload: &models.HostGroupsRespV1{}}, nil
}
func (stubGroups) UpdateHostGroups(*host_group.UpdateHostGroupsParams, ...host_group.ClientOption) (*host_group.UpdateHostGroupsOK, error) {
	return &host_group.UpdateHostGroupsOK{Payload: &models.HostGroupsRespV1{}}, nil
}
func (stubGroups) DeleteHostGroups(*host_group.DeleteHostGroupsParams, ...host_group.ClientOption) (*host_group.DeleteHostGroupsOK, error) {
	return &host_group.DeleteHostGroupsOK{Payload: &models.MsaQueryResponse{}}, nil
}
func (stubGroups) PerformGroupAction(*host_group.PerformGroupActionParams, ...host_group.ClientOption) (*host_group.PerformGroupActionOK, error) {
	return &host_group.PerformGroupActionOK{Payload: &models.HostGroupsRespV1{}}, nil
}

type stubServerless struct{}

func (stubServerless) GetCombinedVulnerabilitiesSARIF(*serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFParams, ...serverless_vulnerabilities.ClientOption) (any, error) {
	// The module decodes the raw response body; return the live-shape SARIF
	// envelope (resources is a single object whose runs field is the payload).
	return []byte(`{"resources":{"version":"2.1.0","runs":[]},"errors":[]}`), nil
}

// connectTestServer registers the host and host-group modules on a server and
// returns a connected in-memory client session.
func connectTestServer(t *testing.T) *mcp.ClientSession {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "falcon-mcp-test", Version: "test"}, nil)
	reg := base.ServerRegistrar(srv)
	for _, m := range []base.Module{&hostsmod.Module{API: stubHosts{}, Concurrency: 4, Logger: testutil.DiscardLogger()}, &hostgroups.Module{API: stubGroups{}, Logger: testutil.DiscardLogger()}, &serverless.Module{API: stubServerless{}, Logger: testutil.DiscardLogger()}} {
		m.RegisterTools(reg)
		m.RegisterResources(srv)
	}

	cs := testutil.NewClientSession(context.Background(), t, srv)
	return cs
}

func TestToolsAndResourcesAreRegistered(t *testing.T) {
	cs := connectTestServer(t)
	ctx := context.Background()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	want := map[string]bool{
		"falcon_search_hosts": false, "falcon_get_host_details": false,
		"falcon_search_host_groups": false, "falcon_search_host_group_members": false,
		"falcon_create_host_group": false, "falcon_update_host_group": false,
		"falcon_delete_host_groups": false, "falcon_perform_host_group_action": false,
		"falcon_search_serverless_vulnerabilities": false,
	}
	for _, tool := range tools.Tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("tool %q not registered", name)
		}
	}

	resources, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	// Resources are keyed by URI and must carry the Python-matching, falcon_-
	// prefixed name so falcon-mcp clients see identical resource identities.
	gotNameForURI := map[string]string{}
	for _, r := range resources.Resources {
		gotNameForURI[r.URI] = r.Name
	}
	wantResources := map[string]string{
		"falcon://hosts/search/fql-guide":               "falcon_search_hosts_fql_guide",
		"falcon://host-groups/search/fql-guide":         "falcon_search_host_groups_fql_guide",
		"falcon://serverless/vulnerabilities/fql-guide": "falcon_serverless_vulnerabilities_fql_guide",
	}
	for uri, wantName := range wantResources {
		name, ok := gotNameForURI[uri]
		if !ok {
			t.Errorf("resource %q not registered", uri)
			continue
		}
		if name != wantName {
			t.Errorf("resource %q name = %q, want %q", uri, name, wantName)
		}
	}
}

func TestCallToolEndToEnd(t *testing.T) {
	cs := connectTestServer(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "falcon_search_hosts",
		Arguments: map[string]any{"filter": "platform_name:'Windows'"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error result: %+v", res.Content)
	}
	// The result must carry native structured JSON (an object with a
	// "resources" array), not a stringified blob in text content.
	if res.StructuredContent == nil {
		t.Fatalf("expected structured content")
	}
	obj, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content should be a JSON object, got %T", res.StructuredContent)
	}
	if _, ok := obj["resources"]; !ok {
		t.Fatalf("structured content missing resources field: %v", obj)
	}
}

// TestMetaShapeEndToEnd drives a real tools/call over the in-memory transport and
// asserts the trimmed meta arrives as native structured JSON: the pagination
// block, query duration, and trace ID a client acts on, with the endpoint-specific
// extras (powered_by here) dropped. It also pins the advertised output schema so a
// client can discover the pagination contract from tools/list rather than guessing
// a per-endpoint shape.
func TestMetaShapeEndToEnd(t *testing.T) {
	cs := connectTestServer(t)
	ctx := context.Background()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "falcon_search_hosts",
		Arguments: map[string]any{"filter": "platform_name:'Windows'"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error result: %+v", res.Content)
	}
	obj, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content should be a JSON object, got %T", res.StructuredContent)
	}
	meta, ok := obj["meta"].(map[string]any)
	if !ok {
		t.Fatalf("result must carry a meta object, got %#v", obj["meta"])
	}

	pagination, ok := meta["pagination"].(map[string]any)
	if !ok {
		t.Fatalf("meta must carry a pagination object, got %#v", meta["pagination"])
	}
	if got := pagination["total"]; got != float64(120) {
		t.Errorf("meta.pagination.total = %#v, want 120", got)
	}
	if got := pagination["limit"]; got != float64(50) {
		t.Errorf("meta.pagination.limit = %#v, want 50", got)
	}
	// A numeric offset stays numeric end to end, so a caller can feed it back into an
	// integer-typed offset input without a type conversion. Endpoints returning an
	// opaque cursor instead emit a string; the advertised schema admits both.
	if got := pagination["offset"]; got != float64(10) {
		t.Errorf("meta.pagination.offset = %#v, want 10", got)
	}
	if got := meta["query_time"]; got != 0.02 {
		t.Errorf("meta.query_time = %#v, want 0.02", got)
	}
	if got := meta["trace_id"]; got != "trace-conformance" {
		t.Errorf("meta.trace_id = %#v, want trace-conformance", got)
	}
	for _, dropped := range []string{"powered_by", "writes", "errors"} {
		if _, ok := meta[dropped]; ok {
			t.Errorf("meta must not carry %q, got %#v", dropped, meta)
		}
	}

	// The advertised schema must describe meta rather than accept anything, so a
	// client can learn the contract from tools/list.
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var rawSchema any
	for _, tool := range tools.Tools {
		if tool.Name == "falcon_search_hosts" {
			rawSchema = tool.OutputSchema
			break
		}
	}
	if rawSchema == nil {
		t.Fatal("falcon_search_hosts must advertise an output schema")
	}
	// The schema crosses the wire as JSON, so walk it as decoded data: that is
	// exactly what a client sees.
	encoded, err := json.Marshal(rawSchema)
	if err != nil {
		t.Fatalf("marshal output schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatalf("unmarshal output schema: %v", err)
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("output schema must have properties, got %s", encoded)
	}
	metaSchema, ok := props["meta"].(map[string]any)
	if !ok {
		t.Fatalf("output schema must describe the meta property, got %s", encoded)
	}
	metaProps, ok := metaSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("meta schema must describe its properties rather than accept anything, got %v", metaSchema)
	}
	pagingSchema, ok := metaProps["pagination"].(map[string]any)
	if !ok {
		t.Fatalf("meta schema must describe pagination, got %v", metaProps)
	}
	pagingProps, ok := pagingSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("pagination schema must describe its properties, got %v", pagingSchema)
	}
	for _, field := range []string{"total", "limit", "offset", "next"} {
		if _, ok := pagingProps[field]; !ok {
			t.Errorf("pagination schema must describe %q, got %v", field, pagingProps)
		}
	}
}

// TestOffsetInputsAreIntegers walks every tool a fully-enabled server advertises and
// asserts each one taking an offset declares it as a non-negative integer. The
// offset a tool reports in meta.pagination is numeric, so a caller must be able to
// hand that value straight back; a string-typed offset input rejects it and breaks
// the documented paging round-trip.
//
// This is deliberately fleet-wide rather than per-module: the tools taking an offset
// span two dozen modules, and a per-module assertion only covers whichever ones
// somebody remembered to write. A new paginated tool is checked here the moment it
// is registered.
func TestOffsetInputsAreIntegers(t *testing.T) {
	cs := connectNewServer(t, &config.Config{})

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools.Tools) == 0 {
		t.Fatal("no tools advertised; the fleet-wide sweep would be vacuous")
	}

	var checked int
	for _, tool := range tools.Tools {
		if tool.InputSchema == nil {
			continue
		}
		// The schema crosses the wire as JSON, so walk it as decoded data: that is
		// exactly what a client validates against.
		encoded, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Errorf("%s: marshal input schema: %v", tool.Name, err)
			continue
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(encoded, &schema); err != nil {
			t.Errorf("%s: unmarshal input schema: %v", tool.Name, err)
			continue
		}
		rawOffset, ok := schema.Properties["offset"]
		if !ok {
			continue
		}
		// Only the offset property is decoded into a typed shape. Other properties
		// legitimately carry a type array (e.g. ["null","array"]), which a single
		// string field could not hold.
		var offset struct {
			Type    string   `json:"type"`
			Minimum *float64 `json:"minimum"`
		}
		if err := json.Unmarshal(rawOffset, &offset); err != nil {
			t.Errorf("%s: unmarshal offset property: %v", tool.Name, err)
			continue
		}
		checked++
		if offset.Type != "integer" {
			t.Errorf("%s: offset input type = %q, want integer", tool.Name, offset.Type)
		}
		if offset.Minimum == nil || *offset.Minimum != 0 {
			t.Errorf("%s: offset input minimum = %v, want 0", tool.Name, offset.Minimum)
		}
	}
	// A refactor that stops advertising offset inputs would otherwise make every
	// assertion above vacuously pass.
	if checked == 0 {
		t.Error("no tool advertised an offset input; expected the paginated search tools")
	}
	t.Logf("checked %d offset-taking tools of %d advertised", checked, len(tools.Tools))
}

// TestModuleSelectionEndToEnd drives a real New-built server over the in-memory
// transport and asserts the tools/list surface reflects the --modules allowlist:
// only the hosts module's tools are advertised, and detection/host-group tools
// are absent. A zero API is safe here — New only reads sub-client pointers to
// register tools (see TestServerMCPNotNil), it makes no API calls.
func TestModuleSelectionEndToEnd(t *testing.T) {
	srv, err := New(
		&config.Config{Modules: []string{"hosts"}},
		&client.CrowdStrikeAPISpecification{},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	cs := testutil.NewClientSession(ctx, t, srv.MCP())

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range tools.Tools {
		got[tool.Name] = true
	}
	if !got["falcon_search_hosts"] {
		t.Errorf("hosts module tool falcon_search_hosts not advertised")
	}
	for _, absent := range []string{"falcon_search_detections", "falcon_search_host_groups"} {
		if got[absent] {
			t.Errorf("tool %q advertised, want absent (module not enabled)", absent)
		}
	}
}

// connectNewServer builds a full New server (zero API — registration only, no
// API calls) and returns a connected in-memory client session.
func connectNewServer(t *testing.T, cfg *config.Config) *mcp.ClientSession {
	t.Helper()
	srv, err := New(cfg, &client.CrowdStrikeAPISpecification{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	ctx := context.Background()
	cs := testutil.NewClientSession(ctx, t, srv.MCP())
	return cs
}

// TestInitializeInstructions asserts the initialize response carries exactly the
// wired serverInstructions value for each transport mode: normal mode gets the
// base instructions, dynamic mode appends the search/execute loop guidance.
func TestInitializeInstructions(t *testing.T) {
	tests := []struct {
		name    string
		dynamic bool
	}{
		{name: "normal mode", dynamic: false},
		{name: "dynamic mode", dynamic: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := connectNewServer(t, &config.Config{Dynamic: tc.dynamic})
			want := serverInstructions(tc.dynamic)
			if got := cs.InitializeResult().Instructions; got != want {
				t.Fatalf("instructions = %q, want %q", got, want)
			}
		})
	}
}

// TestPromptsEndToEnd asserts the detections FQL-builder prompt is advertised
// with the falcon_ prefix and renders a non-empty message via prompts/get.
func TestPromptsEndToEnd(t *testing.T) {
	cs := connectNewServer(t, &config.Config{Modules: []string{"detections"}})
	ctx := context.Background()

	list, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	found := false
	for _, p := range list.Prompts {
		if p.Name == "falcon_build_detection_filter" {
			found = true
		}
	}
	if !found {
		t.Fatalf("prompt falcon_build_detection_filter not advertised; got %+v", list.Prompts)
	}

	get, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "falcon_build_detection_filter",
		Arguments: map[string]string{"status": "new"},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(get.Messages) == 0 {
		t.Fatalf("prompt returned no messages")
	}
}

// listAdvertisedTools connects to cs and returns the advertised tool names as a
// set, failing the test on error.
func listAdvertisedTools(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range tools.Tools {
		got[tool.Name] = true
	}
	return got
}

// TestCoreToolSurfaceEndToEnd pins the restructured meta-tool surface on a full
// server: the always-on falcon_list_enabled_tools and the normal-only
// falcon_check_connectivity/falcon_list_enabled_modules are advertised, and the
// removed falcon_list_modules is gone.
func TestCoreToolSurfaceEndToEnd(t *testing.T) {
	cs := connectNewServer(t, &config.Config{Modules: []string{"hosts"}})
	got := listAdvertisedTools(t, cs)

	for _, present := range []string{"falcon_list_enabled_tools", "falcon_check_connectivity", "falcon_list_enabled_modules"} {
		if !got[present] {
			t.Errorf("core tool %q not advertised", present)
		}
	}
	if got["falcon_list_modules"] {
		t.Errorf("removed tool falcon_list_modules is still advertised")
	}
}

// TestAggregateToolsEndToEnd asserts the aggregate tools ported in items B and D
// are advertised by their enabling modules on a full server.
func TestAggregateToolsEndToEnd(t *testing.T) {
	cs := connectNewServer(t, &config.Config{Modules: []string{"detections", "cases"}})
	got := listAdvertisedTools(t, cs)

	for _, name := range []string{
		"falcon_aggregate_detections",
		"falcon_aggregate_case_slas",
		"falcon_aggregate_case_templates",
		"falcon_aggregate_case_access_tags",
		"falcon_aggregate_case_notification_groups",
		"falcon_aggregate_case_file_details",
	} {
		if !got[name] {
			t.Errorf("aggregate tool %q not advertised", name)
		}
	}
}

// TestReadOnlyPolicyEndToEnd asserts --read-only drops mutating module tools
// while keeping read-only ones, over a full server.
func TestReadOnlyPolicyEndToEnd(t *testing.T) {
	cs := connectNewServer(t, &config.Config{Modules: []string{"hostgroups"}, ReadOnly: true})
	got := listAdvertisedTools(t, cs)

	if !got["falcon_search_host_groups"] {
		t.Errorf("read-only search tool falcon_search_host_groups dropped, want kept")
	}
	for _, mutating := range []string{"falcon_create_host_group", "falcon_delete_host_groups", "falcon_perform_host_group_action"} {
		if got[mutating] {
			t.Errorf("mutating tool %q advertised under --read-only, want dropped", mutating)
		}
	}
}

// TestToolAllowlistEndToEnd asserts --tools without --modules yields exactly the
// named tools (plus the always-on core tool), pulling a tool from a module that
// was never wholesale-enabled.
func TestToolAllowlistEndToEnd(t *testing.T) {
	cs := connectNewServer(t, &config.Config{Tools: []string{"falcon_search_hosts"}})
	got := listAdvertisedTools(t, cs)

	if !got["falcon_search_hosts"] {
		t.Errorf("allow-listed tool falcon_search_hosts not advertised")
	}
	// A sibling tool from the same module is not allow-listed, so it must be absent.
	if got["falcon_get_host_details"] {
		t.Errorf("non-allow-listed tool falcon_get_host_details advertised, want absent")
	}
	// A tool from an unrelated module must be absent too.
	if got["falcon_search_detections"] {
		t.Errorf("tool from unlisted module advertised, want absent")
	}
	// The always-on core tool is still present.
	if !got["falcon_list_enabled_tools"] {
		t.Errorf("always-on falcon_list_enabled_tools not advertised under allow-list")
	}
}

// TestToolDenylistEndToEnd asserts --exclude-tools drops a named tool while
// leaving its module's other tools in place.
func TestToolDenylistEndToEnd(t *testing.T) {
	cs := connectNewServer(t, &config.Config{Modules: []string{"hosts"}, ExcludeTools: []string{"falcon_get_host_details"}})
	got := listAdvertisedTools(t, cs)

	if got["falcon_get_host_details"] {
		t.Errorf("deny-listed tool falcon_get_host_details advertised, want dropped")
	}
	if !got["falcon_search_hosts"] {
		t.Errorf("non-deny-listed tool falcon_search_hosts dropped, want kept")
	}
}

// TestUnknownToolNameRejected asserts an allow/deny-list naming no registered
// tool fails New with a wrapped ErrUnknownToolName.
func TestUnknownToolNameRejected(t *testing.T) {
	_, err := New(&config.Config{Tools: []string{"falcon_no_such_tool"}}, &client.CrowdStrikeAPISpecification{})
	if !errors.Is(err, ErrUnknownToolName) {
		t.Fatalf("err = %v, want ErrUnknownToolName", err)
	}
}
