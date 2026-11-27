package entityname

import "testing"

func TestLookalikeBuiltin(t *testing.T) {
	builtins := []string{"EMAIL", "PHONE_NUMBER", "IP_ADDRESS", "CREDIT_CARD_NUMBER", "URL", "SSN"}
	tests := []struct {
		name string
		want string
	}{
		{"EMAIL", ""},
		{"emails", "EMAIL"},
		{"EMIAL", "EMAIL"},
		{"email", "EMAIL"},
		{"credit-card", "CREDIT_CARD_NUMBER"},
		{"phone_number", "PHONE_NUMBER"},
		{"Ip-Address", "IP_ADDRESS"},
		{"PHONE_NUMBRE", "PHONE_NUMBER"},
		{"ACCOUNT_ID", ""},
		{"URLS", ""},
		{"INVOICE", ""},
		{"SSNS", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LookalikeBuiltin(tt.name, builtins); got != tt.want {
				t.Errorf("LookalikeBuiltin(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestWithinOneEdit(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"email", "email", true},
		{"emial", "email", true},
		{"emails", "email", true},
		{"emal", "email", true},
		{"emaik", "email", true},
		{"mealx", "email", false},
		{"em", "email", false},
	}
	for _, tt := range tests {
		if got := withinOneEdit(tt.a, tt.b); got != tt.want {
			t.Errorf("withinOneEdit(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
