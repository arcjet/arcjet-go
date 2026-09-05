// Package agentframework integrates Arcjet Guard with Microsoft Agent
// Framework for Go (github.com/microsoft/agent-framework-go).
//
// GuardTool wraps a tool.FuncTool so every call is evaluated by Arcjet
// before it runs. GuardTools does the same for a list of tools, including
// MCP client tools. GuardMiddleware screens the user text of a run and
// guards every tool the run can see.
//
// The helpers fail closed by default: when policy cannot be evaluated the
// tool does not run and the model receives arcjet.NewGuardUnavailableResult. A
// denial is returned to the model as a successful tool result carrying
// arcjet.GuardDenialResult, never as an error, because the framework hides
// tool error text from the model and aborts a run after repeated errors.
//
// Microsoft Agent Framework for Go is a public preview. This module tracks
// it and may change with it; its own major version stays at zero until the
// framework's API settles. The supported framework range is the go.mod
// requirement.
package agentframework
