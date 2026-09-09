package agentframework

import (
	"fmt"

	"github.com/microsoft/agent-framework-go/tool"

	"github.com/arcjet/arcjet-go"
)

// GuardTools wraps every tool in tools that implements tool.FuncTool and for
// which policy returns true. Tools that are not function tools, tools the
// policy declines, and tools already wrapped by GuardTool pass through
// unchanged, so the result can be handed to the agent or to mcptool.AddTool
// in place of the input.
//
// MCP client tools from mcptool.ListTools and agent-as-tool values are
// function tools, so this covers them. Hosted tools execute at the provider
// and cannot be guarded; they pass through.
//
// policy is where a caller switches on tool.Name() to pick a hardcoded
// Action for each tool.
//
// A guarded tool keeps the wrapped tool's ReturnSchema, so re-exporting one
// through mcptool.AddTool publishes that schema as the MCP output schema
// while a denial returns arcjet.GuardDenialResult instead. An MCP client that
// validates structured output rejects such a denial. Give that tool a
// ToolPolicy whose OnDeny shapes the denial to the tool's own schema, or
// leave its output schema unset.
func GuardTools(client *arcjet.GuardClient, tools []tool.Tool, policy func(tool.Tool) (ToolPolicy, bool)) ([]tool.Tool, error) {
	if client == nil {
		return nil, errNilClient
	}
	if policy == nil {
		return nil, errNilPolicyFunc
	}
	out := make([]tool.Tool, 0, len(tools))
	for _, t := range tools {
		if alreadyGuarded(t) {
			out = append(out, t)
			continue
		}
		ft, ok := t.(tool.FuncTool)
		if !ok {
			out = append(out, t)
			continue
		}
		p, ok := policy(t)
		if !ok {
			out = append(out, t)
			continue
		}
		guarded, err := GuardTool(client, ft, p)
		if err != nil {
			return nil, fmt.Errorf("agentframework: guarding tool %q: %w", t.Name(), err)
		}
		out = append(out, guarded)
	}
	return out, nil
}
