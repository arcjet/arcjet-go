package agentframework

import (
	"context"
	"errors"
	"testing"

	"github.com/microsoft/agent-framework-go/tool"
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
}
