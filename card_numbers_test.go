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
