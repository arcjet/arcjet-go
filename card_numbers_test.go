package arcjet

import (
	"context"
	"testing"
)

func TestDetectCardNumbers(t *testing.T) {
	const text = "card 4111111111111111 and order 12345"
	cards, err := DetectCardNumbers(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 {
		t.Fatalf("got %d cards, want 1: %+v", len(cards), cards)
	}
	c := cards[0]
	if c.Type != SensitiveInfoCreditCardNumber || text[c.Start:c.End] != "4111111111111111" {
		t.Fatalf("got %+v, want the card number", c)
	}
}

func TestDetectCardNumbersFindsNone(t *testing.T) {
	cards, err := DetectCardNumbers(context.Background(), "email a@example.com, order 12345")
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 0 {
		t.Fatalf("got %+v, want none", cards)
	}
}

// These cases differ between the previous issuer table and the shared card
// definition, so they catch an old component being shipped.
var cardDefinitionCases = []struct {
	name string
	card string // "" when the text holds no card
}{
	{"Mastercard 55", "5500000000000004"},
	{"Mir at 17 digits", "22040000000000006"},
	{"mixed separators", "5500 0000-0000 0004"},
	{"no 18-digit numbers starting with 4", ""},
}

const formerlyDetected = "400000000000000002"

func cardDefinitionText(card string) string {
	if card == "" {
		return "card " + formerlyDetected + " ok"
	}
	return "card " + card + " ok"
}

func TestDetectCardNumbersUsesTheSharedDefinition(t *testing.T) {
	for _, tc := range cardDefinitionCases {
		t.Run(tc.name, func(t *testing.T) {
			text := cardDefinitionText(tc.card)
			cards, err := DetectCardNumbers(context.Background(), text)
			if err != nil {
				t.Fatal(err)
			}
			if tc.card == "" {
				if len(cards) != 0 {
					t.Fatalf("got %+v, want none", cards)
				}
				return
			}
			start := len("card ")
			want := DetectedSensitiveInfoEntity{Start: start, End: start + len(tc.card), Type: SensitiveInfoCreditCardNumber}
			if len(cards) != 1 || cards[0] != want {
				t.Fatalf("got %+v, want %+v", cards, want)
			}
		})
	}
}
