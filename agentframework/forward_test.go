package agentframework

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/microsoft/agent-framework-go/tool"
)

type lifecycleTool struct {
	tool.FuncTool
	initialized bool
	closed      bool
}

func (l *lifecycleTool) Initialize(context.Context) error {
	l.initialized = true
	return nil
}

func (l *lifecycleTool) Close() error {
	l.closed = true
	return nil
}

// shelltool.Local owns a shell subprocess and exposes Initialize and Close,
// neither of which is in tool.FuncTool. Dropping them leaks that process.
func TestGuardToolForwardsLifecycleMethods(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	base, _ := newLookupTool(t)
	inner := &lifecycleTool{FuncTool: base}

	guarded := MustGuardTool(client, inner, ToolPolicy{Action: "order.looked-up"})

	closer, ok := guarded.(io.Closer)
	if !ok {
		t.Fatal("guarded tool is not an io.Closer; a wrapped shell tool would leak")
	}
	initializer, ok := guarded.(interface{ Initialize(context.Context) error })
	if !ok {
		t.Fatal("guarded tool has no Initialize")
	}
	if err := initializer.Initialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if !inner.initialized {
		t.Fatal("Initialize did not reach the wrapped tool")
	}
	if !inner.closed {
		t.Fatal("Close did not reach the wrapped tool")
	}
}

// A tool with no lifecycle methods still answers, so a caller's cleanup loop
// does not have to special-case guarded tools.
func TestGuardToolLifecycleIsANoOpWithoutAnInnerImplementation(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	base, _ := newLookupTool(t)
	guarded := MustGuardTool(client, base, ToolPolicy{Action: "order.looked-up"})

	if err := guarded.(io.Closer).Close(); err != nil {
		t.Fatalf("Close = %v, want nil for a tool that has none", err)
	}
}

// Unwrap gives back the tool that was wrapped, for anything the wrapper does
// not forward.
func TestGuardToolUnwrapReturnsTheWrappedTool(t *testing.T) {
	decide := &fakeDecide{resp: allowResponse()}
	client := newTestClient(t, decide)
	base, _ := newLookupTool(t)
	guarded := MustGuardTool(client, base, ToolPolicy{Action: "order.looked-up"})

	unwrapper, ok := guarded.(interface{ Unwrap() tool.FuncTool })
	if !ok {
		t.Fatal("guarded tool does not expose Unwrap")
	}
	if unwrapper.Unwrap() != base {
		t.Fatal("Unwrap did not return the wrapped tool")
	}
}

var _ = errors.Is
