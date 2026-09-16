module github.com/arcjet/arcjet-go/agentframework

go 1.26.0

// Use the SDK from this repository so changes are picked up without a
// release. Downstream consumers ignore replace directives.
replace github.com/arcjet/arcjet-go => ..

require (
	connectrpc.com/connect v1.20.0
	github.com/arcjet/arcjet-go v1.0.0
	github.com/microsoft/agent-framework-go v0.1.0
	github.com/modelcontextprotocol/go-sdk v1.7.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/gofrs/uuid/v5 v5.4.0 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.jetify.com/typeid v1.3.0 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
