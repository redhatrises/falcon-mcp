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

package guardian

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/aidr_events"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

// fakeAPI is a configurable double for the aidr_events api interface. Methods
// under test read a func field when set; every other method returns an empty OK
// so the fake satisfies the whole interface without scripting unused routes.
type fakeAPI struct {
	queryAgents      func(*aidr_events.QueryAgentsV1Params) (*aidr_events.QueryAgentsV1OK, error)
	entitiesAgents   func(*aidr_events.EntitiesAgentsV1Params) (*aidr_events.EntitiesAgentsV1OK, error)
	queryDetections  func(*aidr_events.QueryDetectionsV1Params) (*aidr_events.QueryDetectionsV1OK, error)
	aggAgents        func(*aidr_events.AggregateAgentsV1Params) (*aidr_events.AggregateAgentsV1OK, error)
	aggAgentSessions func(*aidr_events.AggregateAgentSessionsV1Params) (*aidr_events.AggregateAgentSessionsV1OK, error)
	aggTools         func(*aidr_events.AggregateToolsV1Params) (*aidr_events.AggregateToolsV1OK, error)
	aggDetections    func(*aidr_events.AggregateDetectionsV1Params) (*aidr_events.AggregateDetectionsV1OK, error)

	entitiesSessionActivity func(*aidr_events.EntitiesSessionActivityV1Params) (*aidr_events.EntitiesSessionActivityV1OK, error)
	entitiesProcessTree     func(*aidr_events.EntitiesProcessTreeV1Params) (*aidr_events.EntitiesProcessTreeV1OK, error)
	entitiesNetworkEvents   func(*aidr_events.EntitiesNetworkEventsV1Params) (*aidr_events.EntitiesNetworkEventsV1OK, error)
	entitiesFileEvents      func(*aidr_events.EntitiesFileEventsV1Params) (*aidr_events.EntitiesFileEventsV1OK, error)
	entitiesClassifiedFile  func(*aidr_events.EntitiesClassifiedFileAccessV1Params) (*aidr_events.EntitiesClassifiedFileAccessV1OK, error)
	queryToolUsage          func(*aidr_events.QueryToolUsageV1Params) (*aidr_events.QueryToolUsageV1OK, error)

	queryAgentSessions func(*aidr_events.QueryAgentSessionsV1Params) (*aidr_events.QueryAgentSessionsV1OK, error)
	queryTools         func(*aidr_events.QueryToolsV1Params) (*aidr_events.QueryToolsV1OK, error)
	querySkills        func(*aidr_events.QuerySkillsV1Params) (*aidr_events.QuerySkillsV1OK, error)
	aggSkills          func(*aidr_events.AggregateSkillsV1Params) (*aidr_events.AggregateSkillsV1OK, error)
	querySkillUsage    func(*aidr_events.QuerySkillUsageV1Params) (*aidr_events.QuerySkillUsageV1OK, error)
	queryExecutions    func(*aidr_events.QueryExecutionsV1Params) (*aidr_events.QueryExecutionsV1OK, error)
	entitiesExecutions func(*aidr_events.EntitiesExecutionsV1Params) (*aidr_events.EntitiesExecutionsV1OK, error)
	queryPrompts       func(*aidr_events.QueryPromptsV1Params) (*aidr_events.QueryPromptsV1OK, error)
	queryInstalls      func(*aidr_events.QueryAgentInstallationsV1Params) (*aidr_events.QueryAgentInstallationsV1OK, error)
	queryOSUsers       func(*aidr_events.QueryAgentOSUsersV1Params) (*aidr_events.QueryAgentOSUsersV1OK, error)
	queryModels        func(*aidr_events.QueryModelNamesV1Params) (*aidr_events.QueryModelNamesV1OK, error)
	queryMcpServers    func(*aidr_events.QueryMcpServerNamesV1Params) (*aidr_events.QueryMcpServerNamesV1OK, error)
}

func (f *fakeAPI) QueryAgentsV1(p *aidr_events.QueryAgentsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryAgentsV1OK, error) {
	if f.queryAgents != nil {
		return f.queryAgents(p)
	}
	return &aidr_events.QueryAgentsV1OK{Payload: &models.MsahandlerQueryAgentsResponse{}}, nil
}

func (f *fakeAPI) EntitiesAgentsV1(p *aidr_events.EntitiesAgentsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.EntitiesAgentsV1OK, error) {
	if f.entitiesAgents != nil {
		return f.entitiesAgents(p)
	}
	return &aidr_events.EntitiesAgentsV1OK{Payload: &models.MsahandlerEntitiesAgentsResponse{}}, nil
}

func (f *fakeAPI) QueryDetectionsV1(p *aidr_events.QueryDetectionsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryDetectionsV1OK, error) {
	if f.queryDetections != nil {
		return f.queryDetections(p)
	}
	return &aidr_events.QueryDetectionsV1OK{Payload: &models.MsahandlerQueryDetectionsResponse{}}, nil
}

func (f *fakeAPI) AggregateAgentsV1(p *aidr_events.AggregateAgentsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.AggregateAgentsV1OK, error) {
	if f.aggAgents != nil {
		return f.aggAgents(p)
	}
	return &aidr_events.AggregateAgentsV1OK{Payload: &models.MsahandlerAggregateAgentsResponse{}}, nil
}

func (f *fakeAPI) AggregateAgentSessionsV1(p *aidr_events.AggregateAgentSessionsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.AggregateAgentSessionsV1OK, error) {
	if f.aggAgentSessions != nil {
		return f.aggAgentSessions(p)
	}
	return &aidr_events.AggregateAgentSessionsV1OK{Payload: &models.MsahandlerAggregateAgentSessionsResponse{}}, nil
}

func (f *fakeAPI) AggregateToolsV1(p *aidr_events.AggregateToolsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.AggregateToolsV1OK, error) {
	if f.aggTools != nil {
		return f.aggTools(p)
	}
	return &aidr_events.AggregateToolsV1OK{Payload: &models.MsahandlerAggregateToolsResponse{}}, nil
}

func (f *fakeAPI) AggregateDetectionsV1(p *aidr_events.AggregateDetectionsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.AggregateDetectionsV1OK, error) {
	if f.aggDetections != nil {
		return f.aggDetections(p)
	}
	return &aidr_events.AggregateDetectionsV1OK{Payload: &models.MsahandlerAggregateDetectionsResponse{}}, nil
}

// Unused routes: empty-OK stubs so the fake satisfies the api interface.
func (f *fakeAPI) QueryAgentSessionsV1(p *aidr_events.QueryAgentSessionsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryAgentSessionsV1OK, error) {
	if f.queryAgentSessions != nil {
		return f.queryAgentSessions(p)
	}
	return &aidr_events.QueryAgentSessionsV1OK{Payload: &models.MsahandlerQueryAgentSessionsResponse{}}, nil
}
func (f *fakeAPI) QueryToolsV1(p *aidr_events.QueryToolsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryToolsV1OK, error) {
	if f.queryTools != nil {
		return f.queryTools(p)
	}
	return &aidr_events.QueryToolsV1OK{Payload: &models.MsahandlerQueryToolsResponse{}}, nil
}
func (f *fakeAPI) QueryToolUsageV1(p *aidr_events.QueryToolUsageV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryToolUsageV1OK, error) {
	if f.queryToolUsage != nil {
		return f.queryToolUsage(p)
	}
	return &aidr_events.QueryToolUsageV1OK{Payload: &models.MsahandlerQueryToolUsageResponse{}}, nil
}
func (f *fakeAPI) QuerySkillsV1(p *aidr_events.QuerySkillsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QuerySkillsV1OK, error) {
	if f.querySkills != nil {
		return f.querySkills(p)
	}
	return &aidr_events.QuerySkillsV1OK{Payload: &models.MsahandlerQuerySkillsResponse{}}, nil
}
func (f *fakeAPI) AggregateSkillsV1(p *aidr_events.AggregateSkillsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.AggregateSkillsV1OK, error) {
	if f.aggSkills != nil {
		return f.aggSkills(p)
	}
	return &aidr_events.AggregateSkillsV1OK{Payload: &models.MsahandlerAggregateSkillsResponse{}}, nil
}
func (f *fakeAPI) QuerySkillUsageV1(p *aidr_events.QuerySkillUsageV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QuerySkillUsageV1OK, error) {
	if f.querySkillUsage != nil {
		return f.querySkillUsage(p)
	}
	return &aidr_events.QuerySkillUsageV1OK{Payload: &models.MsahandlerQuerySkillUsageResponse{}}, nil
}
func (f *fakeAPI) QueryExecutionsV1(p *aidr_events.QueryExecutionsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryExecutionsV1OK, error) {
	if f.queryExecutions != nil {
		return f.queryExecutions(p)
	}
	return &aidr_events.QueryExecutionsV1OK{Payload: &models.MsahandlerQueryExecutionsResponse{}}, nil
}
func (f *fakeAPI) EntitiesExecutionsV1(p *aidr_events.EntitiesExecutionsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.EntitiesExecutionsV1OK, error) {
	if f.entitiesExecutions != nil {
		return f.entitiesExecutions(p)
	}
	return &aidr_events.EntitiesExecutionsV1OK{Payload: &models.MsahandlerEntitiesExecutionsResponse{}}, nil
}
func (f *fakeAPI) QueryPromptsV1(p *aidr_events.QueryPromptsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryPromptsV1OK, error) {
	if f.queryPrompts != nil {
		return f.queryPrompts(p)
	}
	return &aidr_events.QueryPromptsV1OK{Payload: &models.MsahandlerQueryPromptsResponse{}}, nil
}
func (f *fakeAPI) QueryAgentInstallationsV1(p *aidr_events.QueryAgentInstallationsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryAgentInstallationsV1OK, error) {
	if f.queryInstalls != nil {
		return f.queryInstalls(p)
	}
	return &aidr_events.QueryAgentInstallationsV1OK{Payload: &models.MsahandlerQueryAgentInstallationsResponse{}}, nil
}
func (f *fakeAPI) QueryAgentOSUsersV1(p *aidr_events.QueryAgentOSUsersV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryAgentOSUsersV1OK, error) {
	if f.queryOSUsers != nil {
		return f.queryOSUsers(p)
	}
	return &aidr_events.QueryAgentOSUsersV1OK{Payload: &models.MsahandlerQueryAgentOSUsersResponse{}}, nil
}
func (f *fakeAPI) QueryModelNamesV1(p *aidr_events.QueryModelNamesV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryModelNamesV1OK, error) {
	if f.queryModels != nil {
		return f.queryModels(p)
	}
	return &aidr_events.QueryModelNamesV1OK{Payload: &models.MsahandlerQueryModelNamesResponse{}}, nil
}
func (f *fakeAPI) QueryMcpServerNamesV1(p *aidr_events.QueryMcpServerNamesV1Params, _ ...aidr_events.ClientOption) (*aidr_events.QueryMcpServerNamesV1OK, error) {
	if f.queryMcpServers != nil {
		return f.queryMcpServers(p)
	}
	return &aidr_events.QueryMcpServerNamesV1OK{Payload: &models.MsahandlerQueryMcpServerNamesResponse{}}, nil
}
func (f *fakeAPI) EntitiesSessionActivityV1(p *aidr_events.EntitiesSessionActivityV1Params, _ ...aidr_events.ClientOption) (*aidr_events.EntitiesSessionActivityV1OK, error) {
	if f.entitiesSessionActivity != nil {
		return f.entitiesSessionActivity(p)
	}
	return &aidr_events.EntitiesSessionActivityV1OK{Payload: &models.MsahandlerSessionActivityResponse{}}, nil
}
func (f *fakeAPI) EntitiesProcessTreeV1(p *aidr_events.EntitiesProcessTreeV1Params, _ ...aidr_events.ClientOption) (*aidr_events.EntitiesProcessTreeV1OK, error) {
	if f.entitiesProcessTree != nil {
		return f.entitiesProcessTree(p)
	}
	return &aidr_events.EntitiesProcessTreeV1OK{Payload: &models.MsahandlerProcessTreeResponse{}}, nil
}
func (f *fakeAPI) EntitiesNetworkEventsV1(p *aidr_events.EntitiesNetworkEventsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.EntitiesNetworkEventsV1OK, error) {
	if f.entitiesNetworkEvents != nil {
		return f.entitiesNetworkEvents(p)
	}
	return &aidr_events.EntitiesNetworkEventsV1OK{Payload: &models.MsahandlerNetworkEventsResponse{}}, nil
}
func (f *fakeAPI) EntitiesFileEventsV1(p *aidr_events.EntitiesFileEventsV1Params, _ ...aidr_events.ClientOption) (*aidr_events.EntitiesFileEventsV1OK, error) {
	if f.entitiesFileEvents != nil {
		return f.entitiesFileEvents(p)
	}
	return &aidr_events.EntitiesFileEventsV1OK{Payload: &models.MsahandlerFileEventsResponse{}}, nil
}
func (f *fakeAPI) EntitiesClassifiedFileAccessV1(p *aidr_events.EntitiesClassifiedFileAccessV1Params, _ ...aidr_events.ClientOption) (*aidr_events.EntitiesClassifiedFileAccessV1OK, error) {
	if f.entitiesClassifiedFile != nil {
		return f.entitiesClassifiedFile(p)
	}
	return &aidr_events.EntitiesClassifiedFileAccessV1OK{Payload: &models.MsahandlerClassifiedFileAccessResponse{}}, nil
}

func newModule(f *fakeAPI) *Module {
	return &Module{API: f, Concurrency: 4, Logger: testLogger}
}

func strp(s string) *string { return &s }
func i32(v int32) *int32    { return &v }

// agentsOK builds a QueryAgentsV1OK carrying the given number of agent records
// and an optional pagination block.
func agentsOK(n int, pag *models.MsahandlerPagination) *aidr_events.QueryAgentsV1OK {
	res := make([]*models.MsahandlerAgentResource, n)
	for i := range res {
		res[i] = &models.MsahandlerAgentResource{ID: strp("agent-" + string(rune('a'+i)))}
	}
	return &aidr_events.QueryAgentsV1OK{Payload: &models.MsahandlerQueryAgentsResponse{
		Resources: res,
		Meta:      &models.MsahandlerMSAMeta{Pagination: pag},
	}}
}

func TestSearchAgentsHappyPath(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{queryAgents: func(p *aidr_events.QueryAgentsV1Params) (*aidr_events.QueryAgentsV1OK, error) {
		if base.Deref(p.Product) != "CLAUDE_CODE" {
			t.Errorf("product not normalized: %q", base.Deref(p.Product))
		}
		return agentsOK(1, &models.MsahandlerPagination{Limit: i32(50), Offset: i32(0), Total: i32(1)}), nil
	}}
	_, out, err := newModule(f).searchAgents(context.Background(), nil, SearchAgentsInput{Product: "Claude Code"})
	if err != nil {
		t.Fatalf("searchAgents: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("want 1 resource, got %d", len(out.Resources))
	}
	// Short page: the API total is real and survives.
	if out.Meta == nil || out.Meta.Pagination == nil || out.Meta.Pagination.Total == nil || *out.Meta.Pagination.Total != 1 {
		t.Fatalf("short-page total should survive, got %+v", out.Meta)
	}
}

func TestSearchAgentsFullPageBlanksTotal(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{queryAgents: func(*aidr_events.QueryAgentsV1Params) (*aidr_events.QueryAgentsV1OK, error) {
		return agentsOK(2, &models.MsahandlerPagination{Limit: i32(2), Offset: i32(0), Total: i32(2)}), nil
	}}
	_, out, err := newModule(f).searchAgents(context.Background(), nil, SearchAgentsInput{Limit: 2})
	if err != nil {
		t.Fatalf("searchAgents: %v", err)
	}
	if out.Meta == nil || out.Meta.Pagination == nil {
		t.Fatalf("expected pagination meta, got %+v", out.Meta)
	}
	if out.Meta.Pagination.Total != nil {
		t.Fatalf("full-page total must be blanked, got %v", *out.Meta.Pagination.Total)
	}
}

func TestSearchAgentsScope403(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{queryAgents: func(*aidr_events.QueryAgentsV1Params) (*aidr_events.QueryAgentsV1OK, error) {
		return nil, testutil.StatusErr(403)
	}}
	_, _, err := newModule(f).searchAgents(context.Background(), nil, SearchAgentsInput{})
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *base.Error, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 403 {
		t.Fatalf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if len(apiErr.RequiredScopes) != 1 || apiErr.RequiredScopes[0] != "AIDR:read" {
		t.Fatalf("RequiredScopes = %v, want [AIDR:read]", apiErr.RequiredScopes)
	}
}

func TestNarrowingLadder(t *testing.T) {
	t.Parallel()
	var windows []string
	f := &fakeAPI{queryAgents: func(p *aidr_events.QueryAgentsV1Params) (*aidr_events.QueryAgentsV1OK, error) {
		windows = append(windows, base.Deref(p.TimeRange))
		if base.Deref(p.TimeRange) == "7d" {
			return nil, testutil.StatusErr(504) // refuse the requested window
		}
		return agentsOK(1, nil), nil // a narrower window succeeds
	}}
	_, out, err := newModule(f).searchAgents(context.Background(), nil, SearchAgentsInput{TimeRange: "7d"})
	if err != nil {
		t.Fatalf("searchAgents: %v", err)
	}
	if len(windows) < 2 || windows[0] != "7d" || windows[1] != "24h" {
		t.Fatalf("ladder did not narrow 7d->24h, tried %v", windows)
	}
	if out.Meta == nil || len(out.Meta.Notices) == 0 {
		t.Fatalf("expected a narrowing notice, got %+v", out.Meta)
	}
	if !containsSub(out.Meta.Notices[0], "narrower 24h window") {
		t.Fatalf("notice = %q", out.Meta.Notices[0])
	}
}

func TestBadTimeRangeUnit(t *testing.T) {
	t.Parallel()
	_, _, err := newModule(&fakeAPI{}).searchAgents(context.Background(), nil, SearchAgentsInput{TimeRange: "30m"})
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *base.Error, got %T", err)
	}
	if !containsSub(apiErr.Message, "invalid time_range unit") {
		t.Fatalf("message = %q", apiErr.Message)
	}
}

func TestDetectionsRejects64HexAgentID(t *testing.T) {
	t.Parallel()
	hex64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	_, _, err := newModule(&fakeAPI{}).searchDetections(context.Background(), nil, SearchDetectionsInput{AgentID: hex64})
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *base.Error, got %T", err)
	}
	if !containsSub(apiErr.Message, "64-hex") {
		t.Fatalf("message = %q", apiErr.Message)
	}
}

func TestGetAgentNotFound(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{entitiesAgents: func(*aidr_events.EntitiesAgentsV1Params) (*aidr_events.EntitiesAgentsV1OK, error) {
		return &aidr_events.EntitiesAgentsV1OK{Payload: &models.MsahandlerEntitiesAgentsResponse{}}, nil
	}}
	_, _, err := newModule(f).getAgent(context.Background(), nil, GetAgentInput{AgentID: "missing"})
	var apiErr *base.Error
	if !errors.As(err, &apiErr) || !containsSub(apiErr.Message, "No agent found") {
		t.Fatalf("want not-found error, got %v", err)
	}
}

func TestInventoryRollup(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{
		aggAgents: func(*aidr_events.AggregateAgentsV1Params) (*aidr_events.AggregateAgentsV1OK, error) {
			return &aidr_events.AggregateAgentsV1OK{Payload: &models.MsahandlerAggregateAgentsResponse{
				Resources: []*models.MsahandlerAggregateAgentsBucket{
					{AgentProductName: "Claude Code", Count: float64(3)},
				},
			}}, nil
		},
	}
	_, out, err := newModule(f).getInventory(context.Background(), nil, GetInventoryInput{TimeRange: "7d"})
	if err != nil {
		t.Fatalf("getInventory: %v", err)
	}
	inv, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("want map result, got %T", out)
	}
	agents, ok := inv["agents"].(map[string]any)
	if !ok {
		t.Fatalf("agents section = %T, want map", inv["agents"])
	}
	if total, _ := agents["total"].(int); total != 3 {
		t.Fatalf("total agents = %v, want 3", agents["total"])
	}
	byProduct, ok := agents["by_product"].(map[string]int)
	if !ok || byProduct["Claude Code"] != 3 {
		t.Fatalf("by_product = %v", agents["by_product"])
	}
}

func TestReadOnlyAnnotations(t *testing.T) {
	t.Parallel()
	tools := testutil.CollectTools(newModule(&fakeAPI{}))
	if len(tools) != 25 {
		t.Fatalf("want 25 tools, got %d", len(tools))
	}
	for name, tool := range tools {
		testutil.AssertReadOnlyAnnotations(t, name, tool.Annotations)
	}
}

func containsSub(s, sub string) bool {
	return strings.Contains(s, sub)
}

// fileEventsVertex builds one graph vertex whose single process wrote two
// modules (a sensitive .env path and an ordinary file), preceded by nil edges
// the typed walk must skip.
func fileEventsVertex() []*models.MsahandlerGraphSessionVertex {
	return []*models.MsahandlerGraphSessionVertex{{
		SessionProcessPid: []*models.MsahandlerSessionProcessEdge{
			nil,            // skipped: nil edge
			{Process: nil}, // skipped: nil process
			{
				Process: &models.MsahandlerProcessVertex{
					ImageFileName: strp("python"),
					ModuleWrittenMod: []*models.MsahandlerModuleWrittenEdge{
						nil, // skipped: nil module edge
						{
							EventCloudTime: strp("t1"),
							Module:         &models.MsahandlerModuleRef{TargetFileName: strp("/app/.env"), SHA256HashData: strp("abc")},
						},
						{
							EventCloudTime: strp("t2"),
							Module:         &models.MsahandlerModuleRef{TargetFileName: strp("/app/main.py"), SHA256HashData: strp("def")},
						},
					},
				},
			},
		},
	}}
}

func TestGetFileEvents(t *testing.T) {
	t.Parallel()
	toolRows := []*models.MsahandlerToolUsageResource{
		{AgenticToolName: "Read", AgenticPath: "/app/.env", CommandLine: "cat .env"},
		{AgenticToolName: "Bash", AgenticPath: "/tmp/x", CommandLine: "ls"}, // non-file tool: dropped
	}
	cases := []struct {
		name          string
		sensitiveOnly bool
		limit         int
		wantWrites    int
		wantAccess    int
	}{
		{name: "all", wantWrites: 2, wantAccess: 1},
		{name: "sensitive_only", sensitiveOnly: true, wantWrites: 1, wantAccess: 1},
		{name: "over_limit", limit: 1, wantWrites: 1, wantAccess: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeAPI{
				entitiesFileEvents: func(*aidr_events.EntitiesFileEventsV1Params) (*aidr_events.EntitiesFileEventsV1OK, error) {
					return &aidr_events.EntitiesFileEventsV1OK{Payload: &models.MsahandlerFileEventsResponse{Resources: fileEventsVertex()}}, nil
				},
				queryToolUsage: func(*aidr_events.QueryToolUsageV1Params) (*aidr_events.QueryToolUsageV1OK, error) {
					return &aidr_events.QueryToolUsageV1OK{Payload: &models.MsahandlerQueryToolUsageResponse{Resources: toolRows}}, nil
				},
			}
			_, out, err := newModule(f).getFileEvents(context.Background(), nil, GetFileEventsInput{
				SessionID: "sess-1", SensitiveOnly: tc.sensitiveOnly, Limit: tc.limit,
			})
			if err != nil {
				t.Fatalf("getFileEvents: %v", err)
			}
			data, ok := out.(map[string]any)
			if !ok {
				t.Fatalf("want map result, got %T", out)
			}
			writes, ok := data["module_writes"].([]map[string]any)
			if !ok {
				t.Fatalf("module_writes = %T, want []map[string]any", data["module_writes"])
			}
			access, ok := data["tool_file_access"].([]map[string]any)
			if !ok {
				t.Fatalf("tool_file_access = %T, want []map[string]any", data["tool_file_access"])
			}
			if len(writes) != tc.wantWrites {
				t.Fatalf("module_writes = %d, want %d", len(writes), tc.wantWrites)
			}
			if len(access) != tc.wantAccess {
				t.Fatalf("tool_file_access = %d, want %d", len(access), tc.wantAccess)
			}
			// The "all" case exercises the full typed walk; guard the mapped fields.
			if tc.name == "all" {
				w := writes[0]
				if w["process"] != "python" || w["file"] != "/app/.env" || w["sha256"] != "abc" || w["timestamp"] != "t1" {
					t.Fatalf("first module write = %+v", w)
				}
			}
		})
	}
}

func TestGenerateReport(t *testing.T) {
	t.Parallel()
	// agentFake returns an agent whose SensorId drives the agent_detail fan-out,
	// plus a detection bucket that pickDetectionScore matches by product tag.
	agentFake := func(sensorID string) *fakeAPI {
		return &fakeAPI{
			entitiesAgents: func(*aidr_events.EntitiesAgentsV1Params) (*aidr_events.EntitiesAgentsV1OK, error) {
				return &aidr_events.EntitiesAgentsV1OK{Payload: &models.MsahandlerEntitiesAgentsResponse{
					Resources: []*models.MsahandlerAgentResource{{ID: strp("agent-1"), SensorID: sensorID, AgentProduct: "CLAUDE_CODE"}},
				}}, nil
			},
			aggDetections: func(*aidr_events.AggregateDetectionsV1Params) (*aidr_events.AggregateDetectionsV1OK, error) {
				return &aidr_events.AggregateDetectionsV1OK{Payload: &models.MsahandlerAggregateDetectionsResponse{
					Resources: []*models.MsahandlerAggregateDetectionsBucket{
						{AgentID: strp("sensor-1"), AgenticProductTag: "CLAUDE_CODE", MaxDetectionScore: float64(87)},
					},
				}}, nil
			},
		}
	}
	cases := []struct {
		name       string
		in         GenerateReportInput
		f          *fakeAPI
		wantErrSub string
		wantType   string
		check      func(t *testing.T, data map[string]any)
	}{
		{name: "invalid_type", in: GenerateReportInput{ReportType: "bogus"}, f: &fakeAPI{}, wantErrSub: "invalid report_type"},
		{name: "agent_detail_missing_id", in: GenerateReportInput{ReportType: "agent_detail"}, f: &fakeAPI{}, wantErrSub: "agent_id is required"},
		{
			name:     "fleet_summary",
			in:       GenerateReportInput{ReportType: "fleet_summary", TimeRange: "7d"},
			f:        &fakeAPI{},
			wantType: "fleet_summary",
			check: func(t *testing.T, data map[string]any) {
				inv, ok := data["inventory"].(map[string]any)
				if !ok {
					t.Fatalf("data.inventory = %T, want map", data["inventory"])
				}
				for _, k := range []string{"agents", "sessions", "tools", "detections"} {
					if _, ok := inv[k]; !ok {
						t.Fatalf("inventory missing %q section: %+v", k, inv)
					}
				}
				if _, ok := data["skills"]; !ok {
					t.Fatalf("data missing skills: %+v", data)
				}
			},
		},
		{
			name:     "skill_threat",
			in:       GenerateReportInput{ReportType: "skill_threat"},
			f:        &fakeAPI{},
			wantType: "skill_threat",
			check: func(t *testing.T, data map[string]any) {
				if _, ok := data["skills"]; !ok {
					t.Fatalf("data missing skills: %+v", data)
				}
			},
		},
		{
			name:     "sensitive_access",
			in:       GenerateReportInput{ReportType: "sensitive_access"},
			f:        &fakeAPI{},
			wantType: "sensitive_access",
			check: func(t *testing.T, data map[string]any) {
				if _, ok := data["sensitive_sessions"]; !ok {
					t.Fatalf("data missing sensitive_sessions key: %+v", data)
				}
			},
		},
		{
			name:     "agent_detail_with_sensor",
			in:       GenerateReportInput{ReportType: "agent_detail", AgentID: "agent-1"},
			f:        agentFake("sensor-1"),
			wantType: "agent_detail",
			check: func(t *testing.T, data map[string]any) {
				agent, ok := data["agent"].(map[string]any)
				if !ok {
					t.Fatalf("data.agent = %T, want map", data["agent"])
				}
				if agent["max_detection_score"] != float64(87) {
					t.Fatalf("max_detection_score = %v, want 87", agent["max_detection_score"])
				}
			},
		},
		{
			name:     "agent_detail_no_sensor",
			in:       GenerateReportInput{ReportType: "agent_detail", AgentID: "agent-1"},
			f:        agentFake(""),
			wantType: "agent_detail",
			check: func(t *testing.T, data map[string]any) {
				agent, ok := data["agent"].(map[string]any)
				if !ok {
					t.Fatalf("data.agent = %T, want map", data["agent"])
				}
				score, ok := agent["max_detection_score"].(map[string]any)
				if !ok {
					t.Fatalf("max_detection_score = %T, want map", agent["max_detection_score"])
				}
				if msg, _ := score["error"].(string); !containsSub(msg, "SensorId") {
					t.Fatalf("max_detection_score error = %v, want missing-aid message", score["error"])
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, out, err := newModule(tc.f).generateReport(context.Background(), nil, tc.in)
			if tc.wantErrSub != "" {
				if !errors.Is(err, base.ErrInvalidInput) || !containsSub(err.Error(), tc.wantErrSub) {
					t.Fatalf("want ErrInvalidInput containing %q, got %v", tc.wantErrSub, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("generateReport: %v", err)
			}
			report, ok := out.(map[string]any)
			if !ok {
				t.Fatalf("want map result, got %T", out)
			}
			if report["report_type"] != tc.wantType {
				t.Fatalf("report_type = %v, want %s", report["report_type"], tc.wantType)
			}
			if tc.check != nil {
				data, ok := report["data"].(map[string]any)
				if !ok {
					t.Fatalf("data = %T, want map", report["data"])
				}
				tc.check(t, data)
			}
		})
	}
}

func TestGetSessionActivity(t *testing.T) {
	t.Parallel()
	sessionOK := func(n int) *fakeAPI {
		return &fakeAPI{entitiesSessionActivity: func(*aidr_events.EntitiesSessionActivityV1Params) (*aidr_events.EntitiesSessionActivityV1OK, error) {
			res := make([]*models.MsahandlerSessionActivityVertex, n)
			for i := range res {
				res[i] = &models.MsahandlerSessionActivityVertex{}
			}
			return &aidr_events.EntitiesSessionActivityV1OK{Payload: &models.MsahandlerSessionActivityResponse{Resources: res}}, nil
		}}
	}
	cases := []struct {
		name       string
		in         GetSessionActivityInput
		f          *fakeAPI
		wantErrSub string
		wantSlice  bool // true => result is []*vertex; false => single *vertex
	}{
		{name: "single", in: GetSessionActivityInput{SessionID: "s1"}, f: sessionOK(1)},
		{name: "multiple", in: GetSessionActivityInput{SessionID: "s1, s2"}, f: sessionOK(2), wantSlice: true},
		{name: "empty_tokens", in: GetSessionActivityInput{SessionID: " , , "}, f: &fakeAPI{}, wantErrSub: "No valid session IDs"},
		{name: "not_found", in: GetSessionActivityInput{SessionID: "s1"}, f: sessionOK(0), wantErrSub: "No session(s) found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, out, err := newModule(tc.f).getSessionActivity(context.Background(), nil, tc.in)
			if tc.wantErrSub != "" {
				var apiErr *base.Error
				if !errors.As(err, &apiErr) || !containsSub(apiErr.Message, tc.wantErrSub) {
					t.Fatalf("want error containing %q, got %v", tc.wantErrSub, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("getSessionActivity: %v", err)
			}
			if tc.wantSlice {
				if _, ok := out.([]*models.MsahandlerSessionActivityVertex); !ok {
					t.Fatalf("want []*vertex, got %T", out)
				}
			} else if _, ok := out.(*models.MsahandlerSessionActivityVertex); !ok {
				t.Fatalf("want *vertex, got %T", out)
			}
		})
	}
}

func TestGetDetectionScores(t *testing.T) {
	t.Parallel()
	t.Run("rejects_64hex", func(t *testing.T) {
		t.Parallel()
		hex64 := strings.Repeat("ab", 32)
		_, _, err := newModule(&fakeAPI{}).getDetectionScores(context.Background(), nil, GetDetectionScoresInput{AgentID: hex64})
		var apiErr *base.Error
		if !errors.As(err, &apiErr) || !containsSub(apiErr.Message, "64-hex") {
			t.Fatalf("want 64-hex rejection, got %v", err)
		}
	})
	t.Run("happy_passthrough", func(t *testing.T) {
		t.Parallel()
		var gotProduct string
		f := &fakeAPI{aggDetections: func(p *aidr_events.AggregateDetectionsV1Params) (*aidr_events.AggregateDetectionsV1OK, error) {
			gotProduct = base.Deref(p.Product)
			return &aidr_events.AggregateDetectionsV1OK{Payload: &models.MsahandlerAggregateDetectionsResponse{
				Resources: []*models.MsahandlerAggregateDetectionsBucket{{AgentID: strp("sensor-1"), MaxDetectionScore: float64(42)}},
			}}, nil
		}}
		_, out, err := newModule(f).getDetectionScores(context.Background(), nil, GetDetectionScoresInput{Product: "Claude Code"})
		if err != nil {
			t.Fatalf("getDetectionScores: %v", err)
		}
		if gotProduct != "CLAUDE_CODE" {
			t.Fatalf("product not normalized: %q", gotProduct)
		}
		if len(out.Resources) != 1 {
			t.Fatalf("want 1 bucket, got %d", len(out.Resources))
		}
	})
}

func TestGetClassifiedFileAccess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		count      int
		wantErrSub string
	}{
		{name: "not_found", count: 0, wantErrSub: "No classified file access found for process"},
		{name: "happy", count: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeAPI{entitiesClassifiedFile: func(*aidr_events.EntitiesClassifiedFileAccessV1Params) (*aidr_events.EntitiesClassifiedFileAccessV1OK, error) {
				res := make([]*models.MsahandlerClassifiedFileProcess, tc.count)
				for i := range res {
					res[i] = &models.MsahandlerClassifiedFileProcess{ProcessID: strp("pid-1")}
				}
				return &aidr_events.EntitiesClassifiedFileAccessV1OK{Payload: &models.MsahandlerClassifiedFileAccessResponse{Resources: res}}, nil
			}}
			_, out, err := newModule(f).getClassifiedFileAccess(context.Background(), nil, GetClassifiedFileAccessInput{ProcessID: "pid-1"})
			if tc.wantErrSub != "" {
				var apiErr *base.Error
				if !errors.As(err, &apiErr) || !containsSub(apiErr.Message, tc.wantErrSub) {
					t.Fatalf("want error containing %q, got %v", tc.wantErrSub, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("getClassifiedFileAccess: %v", err)
			}
			if _, ok := out.(*models.MsahandlerClassifiedFileProcess); !ok {
				t.Fatalf("want *MsahandlerClassifiedFileProcess, got %T", out)
			}
		})
	}
}

func TestGraphResults(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		kind       string // "process" or "network"
		resources  int
		errs       int
		wantErrSub string
		wantWarn   bool
	}{
		{name: "process_not_found", kind: "process", wantErrSub: "No session found"},
		{name: "process_warnings", kind: "process", resources: 1, errs: 1, wantWarn: true},
		{name: "process_errors_empty", kind: "process", errs: 1, wantErrSub: "partial failure"},
		{name: "network_not_found", kind: "network", wantErrSub: "No session found"},
		{name: "network_warnings", kind: "network", resources: 1, errs: 1, wantWarn: true},
		{name: "network_errors_empty", kind: "network", errs: 1, wantErrSub: "partial failure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verts := make([]*models.MsahandlerGraphSessionVertex, tc.resources)
			for i := range verts {
				verts[i] = &models.MsahandlerGraphSessionVertex{ID: strp("v1")}
			}
			msaErrs := make([]*models.MsahandlerMSAError, tc.errs)
			for i := range msaErrs {
				msaErrs[i] = &models.MsahandlerMSAError{Code: i32(500), Message: strp("partial failure")}
			}
			f := &fakeAPI{}
			if tc.kind == "process" {
				f.entitiesProcessTree = func(*aidr_events.EntitiesProcessTreeV1Params) (*aidr_events.EntitiesProcessTreeV1OK, error) {
					return &aidr_events.EntitiesProcessTreeV1OK{Payload: &models.MsahandlerProcessTreeResponse{Resources: verts, Errors: msaErrs}}, nil
				}
			} else {
				f.entitiesNetworkEvents = func(*aidr_events.EntitiesNetworkEventsV1Params) (*aidr_events.EntitiesNetworkEventsV1OK, error) {
					return &aidr_events.EntitiesNetworkEventsV1OK{Payload: &models.MsahandlerNetworkEventsResponse{Resources: verts, Errors: msaErrs}}, nil
				}
			}
			var (
				out any
				err error
			)
			if tc.kind == "process" {
				_, out, err = newModule(f).getProcessTree(context.Background(), nil, GetProcessTreeInput{SessionID: "s1"})
			} else {
				_, out, err = newModule(f).getNetworkEvents(context.Background(), nil, GetNetworkEventsInput{SessionID: "s1"})
			}
			if tc.wantErrSub != "" {
				var apiErr *base.Error
				if !errors.As(err, &apiErr) || !containsSub(apiErr.Message, tc.wantErrSub) {
					t.Fatalf("want error containing %q, got %v", tc.wantErrSub, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", tc.kind, err)
			}
			res, ok := out.(map[string]any)
			if !ok {
				t.Fatalf("want map result, got %T", out)
			}
			if tc.wantWarn {
				if _, ok := res["_warnings"]; !ok {
					t.Fatalf("expected _warnings key, got %+v", res)
				}
			}
		})
	}
}

// statusMsgErr is a status error carrying a message body, so tests can exercise
// windowRejected's 400 branch, which inspects the error text for "time_range".
type statusMsgErr struct {
	code int
	msg  string
}

func (e statusMsgErr) Error() string       { return e.msg }
func (e statusMsgErr) IsSuccess() bool     { return e.code >= 200 && e.code < 300 }
func (e statusMsgErr) IsRedirect() bool    { return e.code >= 300 && e.code < 400 }
func (e statusMsgErr) IsClientError() bool { return e.code >= 400 && e.code < 500 }
func (e statusMsgErr) IsServerError() bool { return e.code >= 500 }
func (e statusMsgErr) IsCode(c int) bool   { return e.code == c }

func TestWindowRejected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "504_gateway_timeout", err: testutil.StatusErr(504), want: true},
		{name: "403_forbidden", err: testutil.StatusErr(403), want: false},
		{name: "400_without_time_range", err: statusMsgErr{code: 400, msg: "some other validation error"}, want: false},
		{name: "400_names_time_range", err: statusMsgErr{code: 400, msg: "field 'time_range' exceeds maximum"}, want: true},
		{name: "400_time_range_mixed_case", err: statusMsgErr{code: 400, msg: "TIME_RANGE too wide"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := windowRejected(tc.err); got != tc.want {
				t.Fatalf("windowRejected(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestNarrowingLadderExhausted(t *testing.T) {
	t.Parallel()
	var windows []string
	f := &fakeAPI{queryAgents: func(p *aidr_events.QueryAgentsV1Params) (*aidr_events.QueryAgentsV1OK, error) {
		windows = append(windows, base.Deref(p.TimeRange))
		return nil, testutil.StatusErr(504) // every window is refused
	}}
	_, _, err := newModule(f).searchAgents(context.Background(), nil, SearchAgentsInput{TimeRange: "7d"})
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *base.Error, got %T: %v", err, err)
	}
	// The ladder tried the requested window and every narrower rung.
	if want := []string{"7d", "24h", "6h", "1h"}; !equalStrings(windows, want) {
		t.Fatalf("tried windows %v, want %v", windows, want)
	}
	// The exhaustion guidance must survive on the error message, since a failed
	// call carries no result meta to hold notices.
	if !containsSub(apiErr.Message, "refused every window down to 1h") {
		t.Fatalf("exhaustion notice not folded into error: %q", apiErr.Message)
	}
}

func TestNarrowingLadder400TimeRange(t *testing.T) {
	t.Parallel()
	var windows []string
	f := &fakeAPI{queryAgents: func(p *aidr_events.QueryAgentsV1Params) (*aidr_events.QueryAgentsV1OK, error) {
		windows = append(windows, base.Deref(p.TimeRange))
		if base.Deref(p.TimeRange) == "7d" {
			return nil, statusMsgErr{code: 400, msg: "field 'time_range' window too wide"}
		}
		return agentsOK(1, nil), nil
	}}
	_, out, err := newModule(f).searchAgents(context.Background(), nil, SearchAgentsInput{TimeRange: "7d"})
	if err != nil {
		t.Fatalf("searchAgents: %v", err)
	}
	if len(windows) < 2 || windows[0] != "7d" || windows[1] != "24h" {
		t.Fatalf("ladder did not narrow 7d->24h on a 400+time_range, tried %v", windows)
	}
	if out.Meta == nil || len(out.Meta.Notices) == 0 || !containsSub(out.Meta.Notices[0], "narrower 24h window") {
		t.Fatalf("expected a narrowing notice, got %+v", out.Meta)
	}
}

func TestPivot(t *testing.T) {
	t.Parallel()

	t.Run("product_normalizes_and_returns", func(t *testing.T) {
		t.Parallel()
		var gotProduct string
		f := &fakeAPI{queryAgents: func(p *aidr_events.QueryAgentsV1Params) (*aidr_events.QueryAgentsV1OK, error) {
			gotProduct = base.Deref(p.Product)
			return agentsOK(1, nil), nil
		}}
		_, out, err := newModule(f).pivot(context.Background(), nil, PivotInput{Attribute: "Product", Value: "Claude Code"})
		if err != nil {
			t.Fatalf("pivot Product: %v", err)
		}
		if gotProduct != "CLAUDE_CODE" {
			t.Fatalf("product not normalized: %q", gotProduct)
		}
		if len(out.Resources) != 1 {
			t.Fatalf("want 1 resource, got %d", len(out.Resources))
		}
	})

	t.Run("hostname_passthrough", func(t *testing.T) {
		t.Parallel()
		var gotHost string
		f := &fakeAPI{queryAgents: func(p *aidr_events.QueryAgentsV1Params) (*aidr_events.QueryAgentsV1OK, error) {
			gotHost = base.Deref(p.Hostname)
			return agentsOK(1, nil), nil
		}}
		_, out, err := newModule(f).pivot(context.Background(), nil, PivotInput{Attribute: "HostName", Value: "host-1"})
		if err != nil {
			t.Fatalf("pivot HostName: %v", err)
		}
		if gotHost != "host-1" {
			t.Fatalf("hostname not passed: %q", gotHost)
		}
		if len(out.Resources) != 1 {
			t.Fatalf("want 1 resource, got %d", len(out.Resources))
		}
	})

	t.Run("skill_name_filter", func(t *testing.T) {
		t.Parallel()
		var gotFilter string
		f := &fakeAPI{querySkills: func(p *aidr_events.QuerySkillsV1Params) (*aidr_events.QuerySkillsV1OK, error) {
			gotFilter = base.Deref(p.NameFilter)
			return &aidr_events.QuerySkillsV1OK{Payload: &models.MsahandlerQuerySkillsResponse{
				Resources: []*models.MsahandlerSkillResource{{SkillName: "deploy"}},
			}}, nil
		}}
		_, out, err := newModule(f).pivot(context.Background(), nil, PivotInput{Attribute: "Skill", Value: "deploy"})
		if err != nil {
			t.Fatalf("pivot Skill: %v", err)
		}
		if gotFilter != "deploy" {
			t.Fatalf("skill name_filter not passed: %q", gotFilter)
		}
		if len(out.Resources) != 1 {
			t.Fatalf("want 1 resource, got %d", len(out.Resources))
		}
	})

	t.Run("name_merges_and_dedups_by_aid", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{
			querySkillUsage: func(*aidr_events.QuerySkillUsageV1Params) (*aidr_events.QuerySkillUsageV1OK, error) {
				return &aidr_events.QuerySkillUsageV1OK{Payload: &models.MsahandlerQuerySkillUsageResponse{
					Resources: []*models.MsahandlerSkillUsageResource{{Aid: strp("h1")}, {Aid: strp("h2")}},
				}}, nil
			},
			queryToolUsage: func(*aidr_events.QueryToolUsageV1Params) (*aidr_events.QueryToolUsageV1OK, error) {
				return &aidr_events.QueryToolUsageV1OK{Payload: &models.MsahandlerQueryToolUsageResponse{
					Resources: []*models.MsahandlerToolUsageResource{{Aid: strp("h2")}, {Aid: strp("h3")}}, // h2 duplicates the skill leg
				}}, nil
			},
		}
		_, out, err := newModule(f).pivot(context.Background(), nil, PivotInput{Attribute: "Name", Value: "Bash"})
		if err != nil {
			t.Fatalf("pivot Name: %v", err)
		}
		// h1, h2, h3 — the duplicate h2 from the tool leg is dropped.
		if len(out.Resources) != 3 {
			t.Fatalf("want 3 deduped rows, got %d: %+v", len(out.Resources), out.Resources)
		}
		if out.Meta == nil || out.Meta.Pagination == nil || out.Meta.Pagination.Total == nil || *out.Meta.Pagination.Total != 3 {
			t.Fatalf("synthesized short-page total should be 3, got %+v", out.Meta)
		}
	})

	t.Run("keeps_rows_without_aid", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{
			querySkillUsage: func(*aidr_events.QuerySkillUsageV1Params) (*aidr_events.QuerySkillUsageV1OK, error) {
				return &aidr_events.QuerySkillUsageV1OK{Payload: &models.MsahandlerQuerySkillUsageResponse{
					Resources: []*models.MsahandlerSkillUsageResource{{}, {}}, // no aid: both kept
				}}, nil
			},
		}
		_, out, err := newModule(f).pivot(context.Background(), nil, PivotInput{Attribute: "Name", Value: "Bash"})
		if err != nil {
			t.Fatalf("pivot Name: %v", err)
		}
		if len(out.Resources) != 2 {
			t.Fatalf("rows without aid must all be kept, got %d", len(out.Resources))
		}
	})

	t.Run("invalid_attribute_is_invalid_input", func(t *testing.T) {
		t.Parallel()
		_, _, err := newModule(&fakeAPI{}).pivot(context.Background(), nil, PivotInput{Attribute: "Bogus", Value: "x"})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("want ErrInvalidInput, got %T: %v", err, err)
		}
		if !containsSub(err.Error(), "invalid attribute") {
			t.Fatalf("message = %q", err.Error())
		}
	})
}

// TestSearchHandlers drives the plain search/list handlers that funnel through
// searchList, confirming each wires its filters and unwraps its own payload
// resource field. The shared ladder/meta/403 behavior is covered by the
// searchAgents tests; these guard the per-route params and result type.
func TestSearchHandlers(t *testing.T) {
	t.Parallel()

	t.Run("mcp_servers", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{queryMcpServers: func(*aidr_events.QueryMcpServerNamesV1Params) (*aidr_events.QueryMcpServerNamesV1OK, error) {
			return &aidr_events.QueryMcpServerNamesV1OK{Payload: &models.MsahandlerQueryMcpServerNamesResponse{
				Resources: []*models.MsahandlerMCPServerResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).searchMCPServers(context.Background(), nil, SearchMCPServersInput{})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("searchMCPServers: err=%v n=%d", err, len(out.Resources))
		}
	})

	t.Run("tools_passes_sensor_id", func(t *testing.T) {
		t.Parallel()
		var gotSensor string
		f := &fakeAPI{queryTools: func(p *aidr_events.QueryToolsV1Params) (*aidr_events.QueryToolsV1OK, error) {
			gotSensor = base.Deref(p.SensorID)
			return &aidr_events.QueryToolsV1OK{Payload: &models.MsahandlerQueryToolsResponse{
				Resources: []*models.MsahandlerToolResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).searchTools(context.Background(), nil, SearchToolsInput{SensorID: "aid-1"})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("searchTools: err=%v n=%d", err, len(out.Resources))
		}
		if gotSensor != "aid-1" {
			t.Fatalf("sensor_id not passed: %q", gotSensor)
		}
	})

	t.Run("tool_usage_passes_filters", func(t *testing.T) {
		t.Parallel()
		var gotTool, gotAid string
		f := &fakeAPI{queryToolUsage: func(p *aidr_events.QueryToolUsageV1Params) (*aidr_events.QueryToolUsageV1OK, error) {
			gotTool, gotAid = base.Deref(p.ToolName), base.Deref(p.Aid)
			return &aidr_events.QueryToolUsageV1OK{Payload: &models.MsahandlerQueryToolUsageResponse{
				Resources: []*models.MsahandlerToolUsageResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).searchToolUsage(context.Background(), nil, SearchToolUsageInput{ToolName: "Bash", Aid: "aid-1"})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("searchToolUsage: err=%v n=%d", err, len(out.Resources))
		}
		if gotTool != "Bash" || gotAid != "aid-1" {
			t.Fatalf("filters not passed: tool=%q aid=%q", gotTool, gotAid)
		}
	})

	t.Run("executions", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{queryExecutions: func(*aidr_events.QueryExecutionsV1Params) (*aidr_events.QueryExecutionsV1OK, error) {
			return &aidr_events.QueryExecutionsV1OK{Payload: &models.MsahandlerQueryExecutionsResponse{
				Resources: []*models.MsahandlerExecutionResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).searchExecutions(context.Background(), nil, SearchExecutionsInput{})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("searchExecutions: err=%v n=%d", err, len(out.Resources))
		}
	})

	t.Run("prompts", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{queryPrompts: func(*aidr_events.QueryPromptsV1Params) (*aidr_events.QueryPromptsV1OK, error) {
			return &aidr_events.QueryPromptsV1OK{Payload: &models.MsahandlerQueryPromptsResponse{
				Resources: []*models.MsahandlerPromptResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).searchPrompts(context.Background(), nil, SearchPromptsInput{SessionID: "s1"})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("searchPrompts: err=%v n=%d", err, len(out.Resources))
		}
	})

	t.Run("skills", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{querySkills: func(*aidr_events.QuerySkillsV1Params) (*aidr_events.QuerySkillsV1OK, error) {
			return &aidr_events.QuerySkillsV1OK{Payload: &models.MsahandlerQuerySkillsResponse{
				Resources: []*models.MsahandlerSkillResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).searchSkills(context.Background(), nil, SearchSkillsInput{})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("searchSkills: err=%v n=%d", err, len(out.Resources))
		}
	})

	t.Run("skill_usage", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{querySkillUsage: func(*aidr_events.QuerySkillUsageV1Params) (*aidr_events.QuerySkillUsageV1OK, error) {
			return &aidr_events.QuerySkillUsageV1OK{Payload: &models.MsahandlerQuerySkillUsageResponse{
				Resources: []*models.MsahandlerSkillUsageResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).searchSkillUsage(context.Background(), nil, SearchSkillUsageInput{})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("searchSkillUsage: err=%v n=%d", err, len(out.Resources))
		}
	})

	t.Run("fleet_skill_inventory", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{aggSkills: func(*aidr_events.AggregateSkillsV1Params) (*aidr_events.AggregateSkillsV1OK, error) {
			return &aidr_events.AggregateSkillsV1OK{Payload: &models.MsahandlerAggregateSkillsResponse{
				Resources: []*models.MsahandlerAggregateSkillsBucket{{}},
			}}, nil
		}}
		_, out, err := newModule(f).getFleetSkillInventory(context.Background(), nil, GetFleetSkillInventoryInput{})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("getFleetSkillInventory: err=%v n=%d", err, len(out.Resources))
		}
	})

	t.Run("os_users", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{queryOSUsers: func(*aidr_events.QueryAgentOSUsersV1Params) (*aidr_events.QueryAgentOSUsersV1OK, error) {
			return &aidr_events.QueryAgentOSUsersV1OK{Payload: &models.MsahandlerQueryAgentOSUsersResponse{
				Resources: []*models.MsahandlerOSUserResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).searchOSUsers(context.Background(), nil, SearchOSUsersInput{})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("searchOSUsers: err=%v n=%d", err, len(out.Resources))
		}
	})

	t.Run("installs_normalizes_product", func(t *testing.T) {
		t.Parallel()
		var gotProduct string
		f := &fakeAPI{queryInstalls: func(p *aidr_events.QueryAgentInstallationsV1Params) (*aidr_events.QueryAgentInstallationsV1OK, error) {
			gotProduct = base.Deref(p.Product)
			return &aidr_events.QueryAgentInstallationsV1OK{Payload: &models.MsahandlerQueryAgentInstallationsResponse{
				Resources: []*models.MsahandlerInstallResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).searchInstalls(context.Background(), nil, SearchInstallsInput{Product: "Claude Code"})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("searchInstalls: err=%v n=%d", err, len(out.Resources))
		}
		if gotProduct != "CLAUDE_CODE" {
			t.Fatalf("product not normalized: %q", gotProduct)
		}
	})

	t.Run("models", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{queryModels: func(*aidr_events.QueryModelNamesV1Params) (*aidr_events.QueryModelNamesV1OK, error) {
			return &aidr_events.QueryModelNamesV1OK{Payload: &models.MsahandlerQueryModelNamesResponse{
				Resources: []*models.MsahandlerModelResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).searchModels(context.Background(), nil, SearchModelsInput{})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("searchModels: err=%v n=%d", err, len(out.Resources))
		}
	})

	t.Run("agent_sessions", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{queryAgentSessions: func(*aidr_events.QueryAgentSessionsV1Params) (*aidr_events.QueryAgentSessionsV1OK, error) {
			return &aidr_events.QueryAgentSessionsV1OK{Payload: &models.MsahandlerQueryAgentSessionsResponse{
				Resources: []*models.MsahandlerAgentSessionResource{{}},
			}}, nil
		}}
		_, out, err := newModule(f).getAgentSessions(context.Background(), nil, GetAgentSessionsInput{})
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("getAgentSessions: err=%v n=%d", err, len(out.Resources))
		}
		if out.Note == "" {
			t.Fatal("agent sessions note should be populated")
		}
	})

	t.Run("session_detail", func(t *testing.T) {
		t.Parallel()
		f := &fakeAPI{entitiesExecutions: func(*aidr_events.EntitiesExecutionsV1Params) (*aidr_events.EntitiesExecutionsV1OK, error) {
			return &aidr_events.EntitiesExecutionsV1OK{Payload: &models.MsahandlerEntitiesExecutionsResponse{
				Resources: []*models.MsahandlerExecutionResource{{}},
			}}, nil
		}}
		noActivity := false
		_, out, err := newModule(f).getSessionDetail(context.Background(), nil, GetSessionDetailInput{SessionID: "s1", IncludeActivity: &noActivity})
		if err != nil {
			t.Fatalf("getSessionDetail: %v", err)
		}
		res, ok := out.(map[string]any)
		if !ok {
			t.Fatalf("want map result, got %T", out)
		}
		if _, ok := res["executions"]; !ok {
			t.Fatalf("session detail missing executions: %+v", res)
		}
	})

	t.Run("session_detail_not_found", func(t *testing.T) {
		t.Parallel()
		_, _, err := newModule(&fakeAPI{}).getSessionDetail(context.Background(), nil, GetSessionDetailInput{SessionID: "missing"})
		var apiErr *base.Error
		if !errors.As(err, &apiErr) || !containsSub(apiErr.Message, "No session found") {
			t.Fatalf("want not-found, got %v", err)
		}
	})
}

// equalStrings reports whether a and b hold the same elements in order.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
