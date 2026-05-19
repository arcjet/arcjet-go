package arcjet

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// WasmModule is a small helper for executing raw WebAssembly modules with wazero.
//
// Most applications do not need this type; request rules use the SDK's bundled
// analyzers directly.
type WasmModule struct {
	runtime wazero.Runtime
	module  api.Module
}

// NewWasmModule instantiates a raw WebAssembly module.
func NewWasmModule(ctx context.Context, wasm []byte) (*WasmModule, error) {
	if len(wasm) == 0 {
		return nil, fmt.Errorf("arcjet: %w: empty", ErrInvalidWasm)
	}
	rt := wazero.NewRuntime(ctx)
	mod, err := rt.Instantiate(ctx, wasm)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("arcjet: %w: %w", ErrInvalidWasm, err)
	}
	return &WasmModule{runtime: rt, module: mod}, nil
}

// Call invokes an exported WebAssembly function by name.
func (m *WasmModule) Call(ctx context.Context, name string, params ...uint64) ([]uint64, error) {
	if m == nil || m.module == nil {
		return nil, fmt.Errorf("arcjet: %w", ErrWasmClosed)
	}
	fn := m.module.ExportedFunction(name)
	if fn == nil {
		return nil, fmt.Errorf("arcjet: %w: %q", ErrWasmExportNotFound, name)
	}
	return fn.Call(ctx, params...)
}

// Close releases the WebAssembly runtime and module.
func (m *WasmModule) Close(ctx context.Context) error {
	if m == nil || m.runtime == nil {
		return nil
	}
	err := m.runtime.Close(ctx)
	m.runtime = nil
	m.module = nil
	return err
}
