package arcjet

import (
	"context"
	"errors"
	"testing"
)

// answerWasm is a minimal module that exports `answer() -> 42`.
func answerWasm() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x0a, 0x01, 0x06, 0x61, 0x6e, 0x73, 0x77, 0x65, 0x72, 0x00, 0x00,
		0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
	}
}

func TestWasmModuleCall(t *testing.T) {
	mod, err := NewWasmModule(context.Background(), answerWasm())
	if err != nil {
		t.Fatal(err)
	}
	defer mod.Close(context.Background())
	results, err := mod.Call(context.Background(), "answer")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0] != 42 {
		t.Fatalf("result = %#v", results)
	}
}

func TestWasmModuleRejectsEmptyModule(t *testing.T) {
	_, err := NewWasmModule(context.Background(), nil)
	if !errors.Is(err, ErrInvalidWasm) {
		t.Fatalf("expected ErrInvalidWasm, got %v", err)
	}
}

func TestWasmModuleCallMissingExport(t *testing.T) {
	mod, err := NewWasmModule(context.Background(), answerWasm())
	if err != nil {
		t.Fatal(err)
	}
	defer mod.Close(context.Background())
	_, err = mod.Call(context.Background(), "missing")
	if !errors.Is(err, ErrWasmExportNotFound) {
		t.Errorf("expected ErrWasmExportNotFound, got %v", err)
	}
}

func TestWasmModuleCallAfterCloseAndNilReceiver(t *testing.T) {
	mod, err := NewWasmModule(context.Background(), answerWasm())
	if err != nil {
		t.Fatal(err)
	}
	if err := mod.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := mod.Close(context.Background()); err != nil {
		t.Errorf("double close = %v", err)
	}
	_, err = mod.Call(context.Background(), "answer")
	if !errors.Is(err, ErrWasmClosed) {
		t.Errorf("expected ErrWasmClosed, got %v", err)
	}

	var nilMod *WasmModule
	_, err = nilMod.Call(context.Background(), "anything")
	if !errors.Is(err, ErrWasmClosed) {
		t.Errorf("expected ErrWasmClosed on nil receiver, got %v", err)
	}
	if err := nilMod.Close(context.Background()); err != nil {
		t.Errorf("nil receiver Close = %v", err)
	}
}
