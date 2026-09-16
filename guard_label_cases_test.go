package arcjet

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestValidateGuardLabelMatchesSharedCases holds this SDK's label rule to the
// cases every other validator reads: the request side and both policy-side
// copies in the decide service, and the JavaScript and Python SDKs.
//
// This validator is already correct, so the test is a characterization gate
// rather than a fix. Running the shared cases against the one implementation
// known to be right is what proves the cases themselves before two new
// validators are written against them.
//
// The rule it pins matters in one direction in particular: this check must
// never be stricter than the service. A label the service accepts and this
// refuses breaks working code, which is what happened when the service began
// accepting an underscore and this did not.
func TestValidateGuardLabelMatchesSharedCases(t *testing.T) {
	const casesPath = "testdata/guard-label-cases.json"

	raw, err := os.ReadFile(casesPath)
	if err != nil {
		t.Fatalf("read %s: %v", casesPath, err)
	}

	var doc struct {
		Revision int `json:"revision"`
		Cases    []struct {
			Label  string `json:"label"`
			Valid  bool   `json:"valid"`
			Reason string `json:"reason"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", casesPath, err)
	}
	// A path that silently read nothing would leave this gate green while
	// testing no cases at all.
	if len(doc.Cases) == 0 {
		t.Fatalf("%s carried no cases", casesPath)
	}

	for _, tc := range doc.Cases {
		name := tc.Label
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			err := ValidateGuardLabel(tc.Label)
			if (err == nil) != tc.Valid {
				t.Errorf("ValidateGuardLabel(%q) err=%v, want valid=%v (%s)",
					tc.Label, err, tc.Valid, tc.Reason)
			}
		})
	}

	// The byte bound is not a case in the JSON, because a 257-character string
	// is unreadable there.
	t.Run("byte bound", func(t *testing.T) {
		if err := ValidateGuardLabel(strings.Repeat("a", 256)); err != nil {
			t.Errorf("ValidateGuardLabel rejected a 256-byte label: %v", err)
		}
		if err := ValidateGuardLabel(strings.Repeat("a", 257)); err == nil {
			t.Error("ValidateGuardLabel accepted a 257-byte label; want rejected")
		}
	})
}
