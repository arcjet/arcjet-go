package agentframework

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/microsoft/agent-framework-go/message"
	"github.com/microsoft/agent-framework-go/tool"
	"github.com/microsoft/agent-framework-go/tool/mcptool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/arcjet/arcjet-go"
)

// nameOnlyTool implements tool.Tool but not tool.FuncTool.
type nameOnlyTool struct{ name string }

func (n nameOnlyTool) Name() string        { return n.name }
func (n nameOnlyTool) Description() string { return "declaration only" }

func TestGuardToolsWrapsOnlyFuncToolsWithAPolicy(t *testing.T) {
	client := newTestClient(t, &fakeDecide{resp: allowResponse()})
	lookup, _ := newLookupTool(t)
	other, err := functoolNew(t, "other", func(_ context.Context, in lookupArgs) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	hosted := nameOnlyTool{name: "web_search"}

	out, err := GuardTools(client, []tool.Tool{lookup, other, hosted}, func(tl tool.Tool) (ToolPolicy, bool) {
		if tl.Name() == "lookup_order" {
			return ToolPolicy{Action: "order.looked-up"}, true
		}
		return ToolPolicy{}, false
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("len = %d", len(out))
	}
	if _, ok := out[0].(guardedMarker); !ok {
		t.Fatal("lookup_order must be wrapped")
	}
	if out[1] != other {
		t.Fatal("a tool without a policy must pass through unchanged")
	}
	if out[2] != hosted {
		t.Fatal("a non-function tool must pass through unchanged")
	}
}

func TestGuardToolsSkipsAlreadyGuardedTools(t *testing.T) {
	client := newTestClient(t, &fakeDecide{resp: allowResponse()})
	lookup, _ := newLookupTool(t)
	once := MustGuardTool(client, lookup, ToolPolicy{Action: "order.looked-up"})
	all := func(tool.Tool) (ToolPolicy, bool) { return ToolPolicy{Action: "order.looked-up"}, true }
	out, err := GuardTools(client, []tool.Tool{once}, all)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != once {
		t.Fatal("an already guarded tool must be returned as is, not wrapped again")
	}
}

func TestGuardToolsPropagatesConfigurationErrors(t *testing.T) {
	client := newTestClient(t, &fakeDecide{resp: allowResponse()})
	lookup, _ := newLookupTool(t)
	if _, err := GuardTools(client, []tool.Tool{lookup}, nil); !errors.Is(err, errNilPolicyFunc) {
		t.Fatalf("nil policy func: err = %v", err)
	}
	_, err := GuardTools(client, []tool.Tool{lookup}, func(tool.Tool) (ToolPolicy, bool) { return ToolPolicy{}, true })
	if !errors.Is(err, errMissingAction) {
		t.Fatalf("empty action: err = %v", err)
	}
	if !strings.Contains(err.Error(), lookup.Name()) {
		t.Fatalf("err = %q, want it to name the failing tool %q", err, lookup.Name())
	}
}

func TestGuardToolsGuardsMCPClientTools(t *testing.T) {
	ctx := t.Context()
	decide := &fakeDecide{resp: denyRateLimitResponse()}
	client := newTestClient(t, decide)
	lookup, calls := newLookupTool(t)

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := mcp.NewServer(&mcp.Implementation{Name: "orders", Version: "1.0.0"}, nil)
	mcptool.AddTool(server, lookup)
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	session, err := mcptool.Connect(ctx, clientTransport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	remote, err := mcptool.ListTools(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	if len(remote) != 1 {
		t.Fatalf("remote tools = %d", len(remote))
	}

	guarded, err := GuardTools(client, remote, func(tl tool.Tool) (ToolPolicy, bool) {
		return ToolPolicy{Action: "order.looked-up"}, tl.Name() == "lookup_order"
	})
	if err != nil {
		t.Fatal(err)
	}
	ft, ok := guarded[0].(tool.FuncTool)
	if !ok {
		t.Fatalf("guarded MCP tool is %T, want FuncTool", guarded[0])
	}
	out, err := ft.Call(ctx, `{"orderNumber":"o-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	if payload, ok := out.(arcjet.GuardDenialResult); !ok || payload.Reason != "RATE_LIMIT" {
		t.Fatalf("out = %#v", out)
	}
	if calls.Load() != 0 {
		t.Fatal("the remote tool ran despite the denial")
	}

	// A guarded tool also registers on an MCP server unchanged: a client sees
	// the original name and schema, and calling it over MCP yields the denial
	// payload as the tool's result.
	serverTransport2, clientTransport2 := mcp.NewInMemoryTransports()
	server2 := mcp.NewServer(&mcp.Implementation{Name: "orders2", Version: "1.0.0"}, nil)
	mcptool.AddTool(server2, MustGuardTool(client, lookup, ToolPolicy{Action: "order.looked-up"}))
	serverSession2, err := server2.Connect(ctx, serverTransport2, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession2.Close() })
	session2, err := mcptool.Connect(ctx, clientTransport2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session2.Close() })
	remote2, err := mcptool.ListTools(ctx, session2)
	if err != nil {
		t.Fatal(err)
	}
	if len(remote2) != 1 || remote2[0].Name() != "lookup_order" {
		t.Fatalf("server2 exposes %v, want lookup_order", remote2)
	}
	wantSchemaJSON, err := json.Marshal(lookup.Schema())
	if err != nil {
		t.Fatal(err)
	}
	gotSchemaJSON, err := json.Marshal(remote2[0].(tool.SchemaTool).Schema())
	if err != nil {
		t.Fatal(err)
	}
	// Compare the decoded schemas, not the marshaled bytes: lookup.Schema()
	// is a typed *jsonschema.Schema with a fixed field order, while the
	// schema fetched back over MCP decodes into a plain map, whose keys
	// json.Marshal always emits alphabetically. JSON object member order
	// carries no meaning, so only the decoded shape has to match.
	var wantSchema, gotSchema any
	if err := json.Unmarshal(wantSchemaJSON, &wantSchema); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(gotSchemaJSON, &gotSchema); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotSchema, wantSchema) {
		t.Fatalf("schema changed across the guarded MCP server:\n got %s\nwant %s", gotSchemaJSON, wantSchemaJSON)
	}
	over, err := remote2[0].(tool.FuncTool).Call(ctx, `{"orderNumber":"o-2"}`)
	if err != nil {
		t.Fatal(err)
	}
	// The client library sees the guard's structured denial and wraps the
	// whole MCP result in a single text envelope so none of it is lost; the
	// envelope's Text is that whole result as JSON, denial payload included.
	contents, ok := over.([]message.Content)
	if !ok || len(contents) != 1 {
		t.Fatalf("over = %#v, want one message.Content", over)
	}
	text, ok := contents[0].(*message.TextContent)
	if !ok {
		t.Fatalf("content = %T, want *message.TextContent", contents[0])
	}
	var envelope struct {
		StructuredContent arcjet.GuardDenialResult `json:"structuredContent"`
	}
	if err := json.Unmarshal([]byte(text.Text), &envelope); err != nil {
		t.Fatalf("envelope text is not the expected JSON: %v\ntext = %s", err, text.Text)
	}
	if payload := envelope.StructuredContent; !payload.ArcjetDenied || payload.Reason != "RATE_LIMIT" {
		t.Fatalf("denial payload over MCP = %+v, envelope text = %s", payload, text.Text)
	}
	if calls.Load() != 0 {
		t.Fatal("the guarded tool behind the MCP server ran despite the denial")
	}
}
