package rampart

import (
	"reflect"
	"testing"

	arcjet "github.com/arcjet/arcjet-go"
)

func TestLuhn(t *testing.T) {
	tests := []struct {
		digits string
		want   bool
	}{
		{"4111111111111111", true},  // Visa test number
		{"5500005555555559", true},  // MasterCard test number
		{"378282246310005", true},   // Amex test number
		{"4111111111111112", false}, // bad check digit
		{"1234567890123456", false},
		{"79927398713", true},  // classic Luhn example
		{"79927398710", false}, // wrong final digit
	}
	for _, tt := range tests {
		if got := luhn(tt.digits); got != tt.want {
			t.Errorf("luhn(%q) = %v, want %v", tt.digits, got, tt.want)
		}
	}
}

func TestEmailRecognizer(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []DetectedSpan
	}{
		{
			name:  "simple",
			value: "reach me at david@arcjet.com please",
			want: []DetectedSpan{
				{Start: 12, End: 28, Type: arcjet.SensitiveInfoEmail},
			},
		},
		{
			name:  "with plus and dots",
			value: "user.name+tag@sub.example.co",
			want: []DetectedSpan{
				{Start: 0, End: 28, Type: arcjet.SensitiveInfoEmail},
			},
		},
		{
			name:  "no tld",
			value: "not-an-email@localhost",
			want:  nil,
		},
		{
			name:  "missing at",
			value: "plainaddress.com",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EmailRecognizer(tt.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EmailRecognizer(%q) = %+v, want %+v", tt.value, got, tt.want)
			}
		})
	}
}

func TestURLRecognizer(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []DetectedSpan
	}{
		{
			name:  "trailing period trimmed",
			value: "see https://example.com/path.",
			want: []DetectedSpan{
				{Start: 4, End: 28, Type: arcjet.SensitiveInfoURL},
			},
		},
		{
			name:  "trailing comma trimmed",
			value: "visit www.example.com, now",
			want: []DetectedSpan{
				{Start: 6, End: 21, Type: arcjet.SensitiveInfoURL},
			},
		},
		{
			name:  "multiple trailing punctuation",
			value: "(http://example.org)!",
			want: []DetectedSpan{
				{Start: 1, End: 19, Type: arcjet.SensitiveInfoURL},
			},
		},
		{
			name:  "no url",
			value: "just some plain text",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := URLRecognizer(tt.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("URLRecognizer(%q) = %+v, want %+v", tt.value, got, tt.want)
			}
		})
	}
}

func TestIPAddressRecognizer(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []DetectedSpan
	}{
		{
			name:  "ipv4",
			value: "from 192.168.0.1 today",
			want: []DetectedSpan{
				{Start: 5, End: 16, Type: arcjet.SensitiveInfoIPAddress},
			},
		},
		{
			name:  "ipv4 max octets",
			value: "255.255.255.255",
			want: []DetectedSpan{
				{Start: 0, End: 15, Type: arcjet.SensitiveInfoIPAddress},
			},
		},
		{
			name:  "ipv6 full",
			value: "addr 2001:0db8:0000:0000:0000:ff00:0042:8329 end",
			want: []DetectedSpan{
				{Start: 5, End: 44, Type: arcjet.SensitiveInfoIPAddress},
			},
		},
		{
			name:  "ipv6 compressed",
			value: "loopback ::1 here",
			want: []DetectedSpan{
				{Start: 9, End: 12, Type: arcjet.SensitiveInfoIPAddress},
			},
		},
		{
			name:  "ipv6 mid compression",
			value: "2001:db8::1",
			want: []DetectedSpan{
				{Start: 0, End: 11, Type: arcjet.SensitiveInfoIPAddress},
			},
		},
		{
			name:  "clock time is not ipv6",
			value: "at 12:34:56 sharp",
			want:  nil,
		},
		{
			name:  "hex embedded in longer word rejected",
			value: "deadbeef::cafexyz",
			want:  nil,
		},
		{
			name:  "ipv6 preceded by word char rejected",
			value: "zff::1",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IPAddressRecognizer(tt.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IPAddressRecognizer(%q) = %+v, want %+v", tt.value, got, tt.want)
			}
		})
	}
}

func TestSSNRecognizer(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []DetectedSpan
	}{
		{
			name:  "dashed ssn",
			value: "ssn 123-45-6789 on file",
			want: []DetectedSpan{
				{Start: 4, End: 15, Type: arcjet.SensitiveInfoSSN},
			},
		},
		{
			name:  "no dashes not matched",
			value: "123456789",
			want:  nil,
		},
		{
			name:  "wrong grouping",
			value: "12-345-6789",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SSNRecognizer(tt.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SSNRecognizer(%q) = %+v, want %+v", tt.value, got, tt.want)
			}
		})
	}
}

func TestCreditCardRecognizer(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []DetectedSpan
	}{
		{
			name:  "luhn valid plain",
			value: "4111111111111111",
			want: []DetectedSpan{
				{Start: 0, End: 16, Type: arcjet.SensitiveInfoCreditCardNumber},
			},
		},
		{
			name:  "luhn valid with spaces",
			value: "4111 1111 1111 1111",
			want: []DetectedSpan{
				{Start: 0, End: 19, Type: arcjet.SensitiveInfoCreditCardNumber},
			},
		},
		{
			name:  "luhn valid with dashes",
			value: "4111-1111-1111-1111",
			want: []DetectedSpan{
				{Start: 0, End: 19, Type: arcjet.SensitiveInfoCreditCardNumber},
			},
		},
		{
			name:  "invalid checksum rejected",
			value: "4111111111111112",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreditCardRecognizer(tt.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreditCardRecognizer(%q) = %+v, want %+v", tt.value, got, tt.want)
			}
		})
	}
}

func TestIsPhoneNumber(t *testing.T) {
	accept := []string{
		"(555) 234-5678",
		"+1 555 234 5678",
		"555-234-5678",
		"5552345678",
	}
	for _, c := range accept {
		if !isPhoneNumber(c) {
			t.Errorf("isPhoneNumber(%q) = false, want true", c)
		}
	}
	reject := []string{
		"123456",          // bare digit run
		"12345",           // short code
		"SKU12345",        // sku (not all digits from start)
		"255.255.255.255", // IP-like
		"1111111111",      // starts with 1, not a NANP N
	}
	for _, c := range reject {
		if isPhoneNumber(c) {
			t.Errorf("isPhoneNumber(%q) = true, want false", c)
		}
	}
}

func TestPhoneRecognizer(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []DetectedSpan
	}{
		{
			name:  "bracketed area code",
			value: "call (555) 234-5678 now",
			want: []DetectedSpan{
				{Start: 5, End: 19, Type: arcjet.SensitiveInfoPhoneNumber},
			},
		},
		{
			name:  "international",
			value: "+1 555 234 5678",
			want: []DetectedSpan{
				{Start: 0, End: 15, Type: arcjet.SensitiveInfoPhoneNumber},
			},
		},
		{
			name:  "dashed",
			value: "555-234-5678",
			want: []DetectedSpan{
				{Start: 0, End: 12, Type: arcjet.SensitiveInfoPhoneNumber},
			},
		},
		{
			name:  "bare nanp",
			value: "5552345678",
			want: []DetectedSpan{
				{Start: 0, End: 10, Type: arcjet.SensitiveInfoPhoneNumber},
			},
		},
		{
			name:  "bare digit run rejected",
			value: "order 123456 shipped",
			want:  nil,
		},
		{
			name:  "short code rejected",
			value: "12345",
			want:  nil,
		},
		{
			name:  "ip-like rejected",
			value: "255.255.255.255",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PhoneRecognizer(tt.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PhoneRecognizer(%q) = %+v, want %+v", tt.value, got, tt.want)
			}
		})
	}
}

func TestDefaultRecognizersOrder(t *testing.T) {
	if len(DefaultRecognizers) != 5 {
		t.Fatalf("len(DefaultRecognizers) = %d, want 5", len(DefaultRecognizers))
	}
	// Verify the order matches Python's default_recognizers by probing each
	// recognizer with an input only it should match.
	probes := []struct {
		value    string
		wantType arcjet.EntityType
	}{
		{"4111111111111111", arcjet.SensitiveInfoCreditCardNumber},
		{"123-45-6789", arcjet.SensitiveInfoSSN},
		{"a@b.co", arcjet.SensitiveInfoEmail},
		{"https://example.com", arcjet.SensitiveInfoURL},
		{"::1", arcjet.SensitiveInfoIPAddress},
	}
	for i, p := range probes {
		got := DefaultRecognizers[i](p.value)
		if len(got) == 0 {
			t.Errorf("DefaultRecognizers[%d](%q) matched nothing", i, p.value)
			continue
		}
		if got[0].Type != p.wantType {
			t.Errorf("DefaultRecognizers[%d](%q) type = %q, want %q", i, p.value, got[0].Type, p.wantType)
		}
	}
	if got := RunRecognizers("bank account 0123456789", DefaultRecognizers); len(got) != 0 {
		t.Errorf("bank account matched a default recognizer: %+v", got)
	}
}

func TestRunRecognizers(t *testing.T) {
	value := "email a@b.co and card 4111111111111111"
	spans := RunRecognizers(value, DefaultRecognizers)
	var haveCard, haveEmail bool
	for _, s := range spans {
		switch s.Type {
		case arcjet.SensitiveInfoCreditCardNumber:
			haveCard = true
		case arcjet.SensitiveInfoEmail:
			haveEmail = true
		default:
		}
	}
	if !haveCard || !haveEmail {
		t.Errorf("RunRecognizers(%q) = %+v, want both card and email spans", value, spans)
	}
	// Card recognizer runs first, so its span comes before the email span.
	if len(spans) >= 2 && spans[0].Type != arcjet.SensitiveInfoCreditCardNumber {
		t.Errorf("expected first span from credit card recognizer, got %q", spans[0].Type)
	}
}
