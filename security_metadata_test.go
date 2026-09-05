package arcjet

import (
	"reflect"
	"testing"
)

func TestSecurityMetadataProjectsNonEmptyFields(t *testing.T) {
	m := SecurityMetadata{User: "user_alice", Agent: "support-agent", DataClass: "confidential", Reversibility: "irreversible"}
	got := m.Metadata()
	want := Metadata{"user": "user_alice", "agent": "support-agent", "dataClass": "confidential", "reversibility": "irreversible"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Metadata() = %v, want %v", got, want)
	}
	if empty := (SecurityMetadata{}).Metadata(); empty == nil || len(empty) != 0 {
		t.Fatalf("empty projection = %#v, want empty non-nil map", empty)
	}
	full := SecurityMetadata{User: "u", Agent: "a", Workflow: "w", DataClass: "d", Destination: "e", Reversibility: "r", Resource: "s"}.Metadata()
	for _, key := range []string{"user", "agent", "workflow", "dataClass", "destination", "reversibility", "resource"} {
		if _, ok := full[key]; !ok {
			t.Fatalf("missing key %q in %v", key, full)
		}
	}
}
