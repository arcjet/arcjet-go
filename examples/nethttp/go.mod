module github.com/arcjet/arcjet-go/examples/nethttp

go 1.25.0

// Use the SDK from this repository so changes are picked up without a release.
// Remove this line to build against a published version.
replace github.com/arcjet/arcjet-go => ../..

require github.com/arcjet/arcjet-go v0.1.0

require (
	connectrpc.com/connect v1.20.0 // indirect
	github.com/gofrs/uuid/v5 v5.4.0 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	go.jetify.com/typeid v1.3.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
