package arcjet

import (
	"errors"
	"strings"
	"testing"
)

// TestValidateGuardLabel pins the label grammar. ValidateGuardLabel is exported
// for framework integrations to call at construction, so the set it accepts is
// part of the public contract: widening it later is compatible, narrowing it is
// not.
func TestValidateGuardLabel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		label string
		valid bool
	}{
		{"dotted", "refund.issued", true},
		{"dashed", "order.looked-up", true},
		{"underscored", "send_email.invoked", true},
		{"underscore only", "a_b", true},
		{"digits", "rule1.v2", true},
		{"single character", "a", true},

		{"empty", "", false},
		{"leading underscore", "_ab", false},
		{"trailing underscore", "ab_", false},
		{"leading dash", "-ab", false},
		{"trailing dot", "ab.", false},
		{"interior space", "a b", false},
		{"uppercase", "Send_Email", false},
		{"colon", "a:b", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGuardLabel(tc.label)
			if tc.valid && err != nil {
				t.Fatalf("ValidateGuardLabel(%q) = %v; want nil", tc.label, err)
			}
			if !tc.valid {
				if err == nil {
					t.Fatalf("ValidateGuardLabel(%q) = nil; want an error", tc.label)
				}
				if !errors.Is(err, ErrInvalidLabel) {
					t.Fatalf("ValidateGuardLabel(%q) error = %v; want it to wrap ErrInvalidLabel", tc.label, err)
				}
			}
		})
	}
}

// TestValidateGuardLabelLength holds the 256-byte bound.
func TestValidateGuardLabelLength(t *testing.T) {
	atLimit := strings.Repeat("a", 256)
	if err := ValidateGuardLabel(atLimit); err != nil {
		t.Fatalf("ValidateGuardLabel rejected a %d-byte label: %v", len(atLimit), err)
	}
	if err := ValidateGuardLabel(atLimit + "a"); err == nil {
		t.Fatalf("ValidateGuardLabel accepted a %d-byte label; want an error", len(atLimit)+1)
	}
}
