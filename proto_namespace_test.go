package arcjet

import (
	"strings"
	"testing"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1/decidev1alpha1connect"
	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
	"github.com/arcjet/arcjet-go/internal/proto/decide/v2/decidev2connect"
)

// TestVendoredProtoIsNamespaced guards the fix for the protobuf global-registry
// collision (arcjet/arcjet#8213 / ENG-852): the SDK's vendored decide proto
// must register under a distinct descriptor path AND proto package so it cannot
// conflict with Arcjet's canonical decide proto (descriptor path
// proto/decide/... + package proto.decide.*) when both are linked into one Go
// binary. If anyone regenerates these bindings without the namespacing
// pre-process, this test fails before the conflict reaches a running binary.
func TestVendoredProtoIsNamespaced(t *testing.T) {
	cases := []struct {
		name     string
		gotPath  string
		fullName string
	}{
		{
			name:     "v1alpha1",
			gotPath:  decidev1.File_arcjet_sdk_decide_v1alpha1_decide_proto.Path(),
			fullName: string((&decidev1.DecideRequest{}).ProtoReflect().Descriptor().FullName()),
		},
		{
			name:     "v2",
			gotPath:  decidev2.File_arcjet_sdk_decide_v2_decide_proto.Path(),
			fullName: string((&decidev2.GuardRequest{}).ProtoReflect().Descriptor().FullName()),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.HasPrefix(tc.gotPath, "arcjet/sdk/decide/") {
				t.Errorf("descriptor path = %q, want it namespaced under arcjet/sdk/decide/ (would collide with the canonical proto/decide/ path)", tc.gotPath)
			}
			if strings.HasPrefix(tc.gotPath, "proto/decide/") {
				t.Errorf("descriptor path = %q uses the canonical proto/decide/ path and will collide in protoregistry.GlobalFiles", tc.gotPath)
			}
			if !strings.HasPrefix(tc.fullName, "arcjet.sdk.decide.") {
				t.Errorf("message full name = %q, want it namespaced under arcjet.sdk.decide. (would collide with the canonical proto.decide.* names)", tc.fullName)
			}
		})
	}
}

// TestConnectRoutesArePinnedToCanonicalWire guards the other half of the fix:
// although the vendored proto is namespaced, the Connect wire route must stay
// the canonical route that decide.arcjet.com serves and every Arcjet SDK
// shares. The route is pinned by hand precisely because it must not follow the
// namespaced package.
func TestConnectRoutesArePinnedToCanonicalWire(t *testing.T) {
	routes := map[string]string{
		"decide": decidev1alpha1connect.DecideServiceDecideProcedure,
		"report": decidev1alpha1connect.DecideServiceReportProcedure,
		"guard":  decidev2connect.DecideServiceGuardProcedure,
	}
	want := map[string]string{
		"decide": "/proto.decide.v1alpha1.DecideService/Decide",
		"report": "/proto.decide.v1alpha1.DecideService/Report",
		"guard":  "/proto.decide.v2.DecideService/Guard",
	}
	for name, got := range routes {
		if got != want[name] {
			t.Errorf("%s route = %q, want canonical %q", name, got, want[name])
		}
	}
}
