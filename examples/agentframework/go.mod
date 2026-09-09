module github.com/arcjet/arcjet-go/examples/agentframework

go 1.26.0

// Use the SDK and the integration from this repository so changes are picked
// up without a release. Remove these lines to build against published versions.
replace github.com/arcjet/arcjet-go => ../..

replace github.com/arcjet/arcjet-go/agentframework => ../../agentframework

require (
	github.com/anthropics/anthropic-sdk-go v1.68.0
	github.com/arcjet/arcjet-go v1.0.0
	github.com/arcjet/arcjet-go/agentframework v0.0.0
	github.com/microsoft/agent-framework-go v0.1.0
)

require (
	connectrpc.com/connect v1.20.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/gofrs/uuid/v5 v5.4.0 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/invopop/jsonschema v0.14.0 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/standard-webhooks/standard-webhooks/libraries v0.0.1 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	github.com/tidwall/gjson v1.19.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	go.jetify.com/typeid v1.3.0 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.2 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
