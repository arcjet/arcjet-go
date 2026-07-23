package rampart

import (
	"testing"

	arcjet "github.com/arcjet/arcjet-go"
)

func TestNormalizeLabel(t *testing.T) {
	tests := []struct {
		in     string
		want   arcjet.EntityType
		wantOk bool
	}{
		{"O", "", false},
		{"", "", false},
		{"B-GIVEN_NAME", arcjet.SensitiveInfoGivenName, true},
		{"I-SURNAME", arcjet.SensitiveInfoSurname, true},
		{"B-PHONE", arcjet.SensitiveInfoPhoneNumber, true}, // alias PHONE -> PHONE_NUMBER
		{"B-URL", arcjet.SensitiveInfoURL, true},
		{"phone", arcjet.SensitiveInfoPhoneNumber, true}, // lowercase, no prefix
		{"CREDIT_CARD", arcjet.SensitiveInfoCreditCardNumber, true},
		{"ZIP", arcjet.SensitiveInfoZipCode, true},
		{"POSTAL_CODE", arcjet.SensitiveInfoZipCode, true},
		{"B-CITY", arcjet.SensitiveInfoCity, true},
		{"UNKNOWN_THING", "", false},
	}
	for _, tt := range tests {
		got, ok := normalizeLabel(tt.in)
		if ok != tt.wantOk || got != tt.want {
			t.Errorf("normalizeLabel(%q) = (%q,%v), want (%q,%v)", tt.in, got, ok, tt.want, tt.wantOk)
		}
	}
}

// TestModelLabelsMapCleanly ensures every model output label (id2label) strips
// and aliases to a known entity type (except O), so no model prediction is
// silently dropped.
func TestModelLabelsMapCleanly(t *testing.T) {
	for id, label := range id2label {
		if label == "O" {
			continue
		}
		if _, ok := normalizeLabel(label); !ok {
			t.Errorf("model label id=%d %q does not map to an entity type", id, label)
		}
	}
}

// TestEntitiesCoverAllAliases ensures Entities() is the full set of types the
// alias table can produce, so deny=Entities() denies everything Rampart emits.
func TestEntitiesCoverAllAliases(t *testing.T) {
	set := make(map[arcjet.EntityType]struct{})
	for _, e := range Entities() {
		set[e] = struct{}{}
	}
	for raw, mapped := range labelAliases {
		if _, ok := set[mapped]; !ok {
			t.Errorf("alias %q -> %q not present in Entities()", raw, mapped)
		}
	}
	if len(Entities()) != len(rampartEntities) {
		t.Fatalf("Entities() returned %d, want %d", len(Entities()), len(rampartEntities))
	}
}

func TestNumLabels(t *testing.T) {
	if numLabels != 35 {
		t.Fatalf("numLabels = %d, want 35", numLabels)
	}
}
