module github.com/arcjet/arcjet-go/examples/nethttp

go 1.26.0

// Use the SDK from this repository so changes are picked up without a release.
// Remove this line to build against a published version.
replace github.com/arcjet/arcjet-go => ../..

require github.com/arcjet/arcjet-go v1.4.0

require golang.org/x/text v0.44.0 // indirect

require (
	connectrpc.com/connect v1.21.1 // indirect
	github.com/arcjet/arcjet-go/sensitiveinfo/rampart v1.4.0
	github.com/gofrs/uuid/v5 v5.5.1 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	go.jetify.com/typeid v1.3.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/arcjet/arcjet-go/sensitiveinfo/rampart => ../../sensitiveinfo/rampart
