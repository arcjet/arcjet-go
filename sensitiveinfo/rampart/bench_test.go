package rampart

import (
	"context"
	"strings"
	"testing"

	arcjet "github.com/arcjet/arcjet-go"
)

func benchBackend(b *testing.B) arcjet.SensitiveInfoBackend {
	b.Helper()
	backend, err := New(Options{})
	if err != nil {
		b.Fatal(err)
	}
	return backend
}

// BenchmarkDetectShort measures a typical short field (single window).
func BenchmarkDetectShort(b *testing.B) {
	backend := benchBackend(b)
	value := "My name is Sarah and I live in London; email sarah@example.com."
	ents := arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()}
	ctx := context.Background()
	bctx := arcjet.SensitiveInfoBackendContext{}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := backend.Detect(ctx, bctx, value, ents, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDetectFullWindow measures a full 480-char single window.
func BenchmarkDetectFullWindow(b *testing.B) {
	backend := benchBackend(b)
	value := strings.Repeat("Contact Sarah Smith in London. ", 16) // ~480 chars
	if len(value) > modelMaxInputChars {
		value = value[:modelMaxInputChars]
	}
	ents := arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()}
	ctx := context.Background()
	bctx := arcjet.SensitiveInfoBackendContext{}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := backend.Detect(ctx, bctx, value, ents, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDetectMultiWindow measures long input scanned in several windows.
func BenchmarkDetectMultiWindow(b *testing.B) {
	backend := benchBackend(b)
	value := strings.Repeat("Contact Sarah Smith in London. ", 100) // ~3000 chars
	ents := arcjet.SensitiveInfoEntities{Deny: true, Entities: Entities()}
	ctx := context.Background()
	bctx := arcjet.SensitiveInfoBackendContext{}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := backend.Detect(ctx, bctx, value, ents, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenize(b *testing.B) {
	tok := newTokenizer()
	value := "My name is Sarah and I live in London; email sarah@example.com."
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = tok.encode(value)
	}
}

func BenchmarkRecognizers(b *testing.B) {
	value := "Reach me at john.doe@example.com or (555) 234-5678. SSN 123-45-6789. https://example.com/x 10.0.0.1"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = RunRecognizers(value, DefaultRecognizers)
	}
}
