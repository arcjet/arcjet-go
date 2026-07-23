package rampart

import (
	"reflect"
	"testing"

	arcjet "github.com/arcjet/arcjet-go"
)

func TestAggregateTokens(t *testing.T) {
	const value = "wolfgang schmidt lives here"
	tests := []struct {
		name   string
		tokens []rawToken
		want   []DetectedSpan
	}{
		{
			name: "subword continuation merges when I- and whitespace-adjacent",
			tokens: []rawToken{
				{entity: "B-SURNAME", score: 0.9, start: 0, end: 4}, // wolf
				{entity: "I-SURNAME", score: 0.9, start: 4, end: 8}, // gang
			},
			want: []DetectedSpan{{Start: 0, End: 8, Type: arcjet.SensitiveInfoSurname}},
		},
		{
			name: "two B- of same type do not merge",
			tokens: []rawToken{
				{entity: "B-SURNAME", score: 0.9, start: 0, end: 4},
				{entity: "B-SURNAME", score: 0.9, start: 4, end: 8},
			},
			want: []DetectedSpan{
				{Start: 0, End: 4, Type: arcjet.SensitiveInfoSurname},
				{Start: 4, End: 8, Type: arcjet.SensitiveInfoSurname},
			},
		},
		{
			name: "below threshold breaks span",
			tokens: []rawToken{
				{entity: "B-CITY", score: 0.9, start: 0, end: 4},
				{entity: "I-CITY", score: 0.3, start: 4, end: 8},
			},
			want: []DetectedSpan{{Start: 0, End: 4, Type: arcjet.SensitiveInfoCity}},
		},
		{
			name: "O token breaks span",
			tokens: []rawToken{
				{entity: "B-CITY", score: 0.9, start: 0, end: 4},
				{entity: "O", score: 0.9, start: 4, end: 8},
				{entity: "I-CITY", score: 0.9, start: 8, end: 12},
			},
			want: []DetectedSpan{
				{Start: 0, End: 4, Type: arcjet.SensitiveInfoCity},
				{Start: 8, End: 12, Type: arcjet.SensitiveInfoCity},
			},
		},
		{
			name: "non-whitespace gap breaks same-type merge",
			tokens: []rawToken{
				{entity: "B-GIVEN_NAME", score: 0.9, start: 0, end: 4},
				{entity: "I-GIVEN_NAME", score: 0.9, start: 8, end: 12}, // gap 4-8 is "lfga" non-ws
			},
			want: []DetectedSpan{
				{Start: 0, End: 4, Type: arcjet.SensitiveInfoGivenName},
				{Start: 8, End: 12, Type: arcjet.SensitiveInfoGivenName},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aggregateTokens(value, tt.tokens, 0.5)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMergeSpansRecognizerPrecedence(t *testing.T) {
	// A longer model span overlaps a shorter recognizer span; the recognizer
	// must win despite being shorter (group precedence beats length).
	recognizer := []DetectedSpan{{Start: 5, End: 15, Type: arcjet.SensitiveInfoEmail}}
	model := []DetectedSpan{{Start: 0, End: 20, Type: arcjet.SensitiveInfoGivenName}}
	got := mergeSpans([][]DetectedSpan{recognizer, model})
	want := []DetectedSpan{{Start: 5, End: 15, Type: arcjet.SensitiveInfoEmail}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestMergeSpansLongerWinsWithinGroup(t *testing.T) {
	model := []DetectedSpan{
		{Start: 0, End: 5, Type: arcjet.SensitiveInfoCity},
		{Start: 0, End: 10, Type: arcjet.SensitiveInfoStreetName},
	}
	got := mergeSpans([][]DetectedSpan{nil, model})
	want := []DetectedSpan{{Start: 0, End: 10, Type: arcjet.SensitiveInfoStreetName}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestMergeSpansKeepsDisjoint(t *testing.T) {
	model := []DetectedSpan{
		{Start: 10, End: 15, Type: arcjet.SensitiveInfoCity},
		{Start: 0, End: 5, Type: arcjet.SensitiveInfoGivenName},
	}
	got := mergeSpans([][]DetectedSpan{nil, model})
	want := []DetectedSpan{
		{Start: 0, End: 5, Type: arcjet.SensitiveInfoGivenName},
		{Start: 10, End: 15, Type: arcjet.SensitiveInfoCity},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestMergeWindowedSpansUnionsSameType(t *testing.T) {
	// Overlapping same-type partials from adjacent windows union into one span.
	spans := []DetectedSpan{
		{Start: 400, End: 480, Type: arcjet.SensitiveInfoStreetName},
		{Start: 416, End: 500, Type: arcjet.SensitiveInfoStreetName},
	}
	got := mergeWindowedSpans(spans)
	want := []DetectedSpan{{Start: 400, End: 500, Type: arcjet.SensitiveInfoStreetName}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestMergeWindowedSpansKeepsDistinct(t *testing.T) {
	spans := []DetectedSpan{
		{Start: 0, End: 5, Type: arcjet.SensitiveInfoCity},
		{Start: 50, End: 55, Type: arcjet.SensitiveInfoCity},
	}
	got := mergeWindowedSpans(spans)
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct spans, got %+v", got)
	}
}
