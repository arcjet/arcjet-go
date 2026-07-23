package rampart

// Deterministic recognizers that mirror Rampart's redaction layer.
//
// Structured, validatable types (email, URL, IP, phone, SSN, Luhn-valid card
// numbers) are handled here with patterns rather than by the model, which is
// more reliable for them. Recognizers are pure and cheap relative to model
// inference.
//
// Ported from arcjet-py's sensitive-info-rampart recognizers module, which in
// turn mirrors sensitive-info-rampart/src/recognizers.ts in arcjet-js.

import (
	"regexp"

	arcjet "github.com/arcjet/arcjet-go"
)

// Recognizer is a deterministic recognizer: given the full text, it returns the
// spans it matched.
type Recognizer func(value string) []DetectedSpan

// luhn validates a candidate card number with the Luhn checksum. digits must be
// a string of digits with separators already removed.
func luhn(digits string) bool {
	total := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		value := int(digits[i]) - 48
		if double {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		total += value
		double = !double
	}
	return total%10 == 0
}

// matchAll runs a regex over value and maps each match to a DetectedSpan.
func matchAll(value string, pattern *regexp.Regexp, entityType arcjet.EntityType) []DetectedSpan {
	var spans []DetectedSpan
	for _, m := range pattern.FindAllStringIndex(value, -1) {
		spans = append(spans, DetectedSpan{Start: m[0], End: m[1], Type: entityType})
	}
	return spans
}

// Patterns are compiled once at package load so repeated detection is cheap.
// Go's regexp (RE2) treats \d/\w/\b as ASCII by default, matching the Python
// patterns' re.ASCII flag; explicit ASCII character classes are used to make
// that intent unambiguous.
var (
	emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	urlPattern   = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"')]+`)
	ipv4Pattern  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b`)
	// IPv6. The Python pattern wraps the alternation below in
	// (?<![:.\w])...(?![:.\w]) negative look-arounds, which RE2 cannot express.
	//
	// The *trailing* bound cannot be a post-match byte check: RE2 is
	// leftmost-first, so for "2001:db8::1" it would greedily prefer the
	// trailing-colon alternative (matching only "2001:db8::") and a post-hoc
	// reject would then drop the whole match, whereas Python backtracks through
	// the look-ahead to the full "2001:db8::1". To reproduce that backtracking we
	// fold the trailing bound into the pattern as a consuming
	// non-word/non-colon/non-dot (or end-of-text) atom and capture the address in
	// group 1 — RE2 then explores every path and the reported span is group 1.
	// The trailing atom can only be a [^:.\w] byte, which never starts an IPv6
	// address, so consuming it cannot hide a following match. The *leading* bound
	// stays a post-match byte check (a consuming leading atom would swallow the
	// separator between two adjacent addresses and hide the second).
	ipv6Pattern = regexp.MustCompile(
		`(` +
			`(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|` +
			`(?:[A-Fa-f0-9]{1,4}:){1,7}:|` +
			`(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|` +
			`(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|` +
			`(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|` +
			`(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|` +
			`(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|` +
			`[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|` +
			`:(?::[A-Fa-f0-9]{1,4}){1,7}` +
			`)(?:[^:.\w]|$)`)
	ssnPattern = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// Candidate card numbers: 13-19 digits, optionally split by spaces or dashes.
	creditCardPattern = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	cardSepPattern    = regexp.MustCompile(`[ -]`)
	// A phone-number candidate: a maximal run of the characters a phone number
	// is made of (digits, the separators the validator understands, parentheses,
	// and a leading +). Candidates are validated by isPhoneNumber, which enforces
	// the real structure, so this pattern only brackets the run.
	phoneCandidatePattern = regexp.MustCompile(`[+(]?\d[0-9\s()./+-]*`)
)

// urlTrailing is punctuation the greedy URL pattern can absorb from surrounding
// prose (the period ending a sentence, a comma in a list). Trimmed from the
// right edge so the span covers only the URL itself.
const urlTrailing = ".,;:!?)]}'\""

// isWordByte reports whether b is an ASCII word character ([0-9A-Za-z_]).
func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= '0' && b <= '9') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z')
}

// isIPv6BoundByte reports whether b is a byte that the Python negative
// look-arounds (?<![:.\w]) / (?![:.\w]) forbid on either side of an IPv6 match.
func isIPv6BoundByte(b byte) bool {
	return b == ':' || b == '.' || isWordByte(b)
}

// EmailRecognizer is the email address recognizer.
func EmailRecognizer(value string) []DetectedSpan {
	return matchAll(value, emailPattern, arcjet.SensitiveInfoEmail)
}

// URLRecognizer is the URL recognizer. The pattern is greedy, so trailing prose
// punctuation is trimmed from each match to keep the span on the URL itself.
func URLRecognizer(value string) []DetectedSpan {
	var result []DetectedSpan
	for _, span := range matchAll(value, urlPattern, arcjet.SensitiveInfoURL) {
		end := span.End
		for end > span.Start && isTrailing(value[end-1]) {
			end--
		}
		if end > span.Start {
			result = append(result, DetectedSpan{Start: span.Start, End: end, Type: arcjet.SensitiveInfoURL})
		}
	}
	return result
}

// isTrailing reports whether b is one of the URL trailing punctuation bytes.
func isTrailing(b byte) bool {
	for i := range len(urlTrailing) {
		if urlTrailing[i] == b {
			return true
		}
	}
	return false
}

// IPAddressRecognizer is the IPv4 and IPv6 address recognizer.
func IPAddressRecognizer(value string) []DetectedSpan {
	result := matchAll(value, ipv4Pattern, arcjet.SensitiveInfoIPAddress)
	// The IPv6 address is captured in group 1; the trailing bound is consumed by
	// the pattern itself (see ipv6Pattern). Apply the leading bound here: reject a
	// match whose immediately-preceding byte is in [:.\w].
	for _, m := range ipv6Pattern.FindAllStringSubmatchIndex(value, -1) {
		start, end := m[2], m[3]
		if start > 0 && isIPv6BoundByte(value[start-1]) {
			continue
		}
		result = append(result, DetectedSpan{Start: start, End: end, Type: arcjet.SensitiveInfoIPAddress})
	}
	return result
}

// SSNRecognizer is the US Social Security Number recognizer (dashed form).
func SSNRecognizer(value string) []DetectedSpan {
	return matchAll(value, ssnPattern, arcjet.SensitiveInfoSSN)
}

// --- Phone number validation -------------------------------------------------
// Ported from arcjet-analyze/parsers/src/parsers/phone_number.rs so the Rampart
// backend validates phone numbers exactly as the default (WASM) backend does. A
// candidate must parse completely as either a structured phone number (an
// international/trunk +/0 prefix, or a NANP start - a bracketed area code or a
// dot/dash-suffixed exchange) followed by 1-5 digit groups, or as a bare
// 10-digit NANP number NXXNXXXXXX. This rejects bare digit runs (order numbers,
// SKUs), short codes, and IP addresses that a digit-count heuristic would
// misclassify.
//
// Each parser takes (text, pos) and returns the index after what it consumed
// with ok=true, or ok=false on failure - mirroring nom's (remainder, output)
// result.

// isSectionSep reports whether b is one of the section separators "- /.".
func isSectionSep(b byte) bool {
	return b == '-' || b == ' ' || b == '/' || b == '.'
}

// isDigit reports whether b is an ASCII digit.
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// isNanpN reports whether b is a NANP leading digit (2-9, never 0 or 1).
func isNanpN(b byte) bool {
	return b >= '2' && b <= '9'
}

// takeMax1 consumes 1..maxn chars matching pred; ok=false if none match.
func takeMax1(text string, pos, maxn int, pred func(byte) bool) (int, bool) {
	end := pos
	for end < len(text) && end-pos < maxn && pred(text[end]) {
		end++
	}
	if end > pos {
		return end, true
	}
	return 0, false
}

// takeAndVerify consumes exactly length chars, all matching pred; else ok=false.
func takeAndVerify(text string, pos, length int, pred func(byte) bool) (int, bool) {
	if pos+length > len(text) {
		return 0, false
	}
	for k := pos; k < pos+length; k++ {
		if !pred(text[k]) {
			return 0, false
		}
	}
	return pos + length, true
}

// limitedDigits consumes a maximal digit run and requires its length in
// [minn, maxn].
func limitedDigits(text string, pos, minn, maxn int) (int, bool) {
	end := pos
	for end < len(text) && isDigit(text[end]) {
		end++
	}
	if n := end - pos; minn <= n && n <= maxn {
		return end, true
	}
	return 0, false
}

func sectionSep(text string, pos int) (int, bool) {
	if pos < len(text) && isSectionSep(text[pos]) {
		return pos + 1, true
	}
	return 0, false
}

// trunkOrInternational matches ('0' | '+') then 1-4 digits.
func trunkOrInternational(text string, pos int) (int, bool) {
	if pos < len(text) && (text[pos] == '0' || text[pos] == '+') {
		return takeMax1(text, pos+1, 4, isDigit)
	}
	return 0, false
}

// bracketStart matches '(' 2-3 digits ')'.
func bracketStart(text string, pos int) (int, bool) {
	if pos >= len(text) || text[pos] != '(' {
		return 0, false
	}
	end, ok := limitedDigits(text, pos+1, 2, 3)
	if !ok || end >= len(text) || text[end] != ')' {
		return 0, false
	}
	return end + 1, true
}

// nxxSection matches a NANP NXX: leading digit 2-9, then two more digits.
func nxxSection(text string, pos int) (int, bool) {
	end, ok := takeAndVerify(text, pos, 1, isNanpN)
	if !ok {
		return 0, false
	}
	return takeAndVerify(text, end, 2, isDigit)
}

// dotOrDashStart matches an NXX section, then a '.' or '-', where the following
// digit/separator run holds exactly one more separator (so IP-like
// 255.255.255.255 is not a start). Only the NXX + separator is consumed; the
// rest is peeked.
func dotOrDashStart(text string, pos int) (int, bool) {
	end, ok := nxxSection(text, pos)
	if !ok || end >= len(text) || (text[end] != '.' && text[end] != '-') {
		return 0, false
	}
	after := end + 1
	run := after
	for run < len(text) && (isDigit(text[run]) || text[run] == '.' || text[run] == '-') {
		run++
	}
	count := 0
	for c := after; c < run; c++ {
		if text[c] == '.' || text[c] == '-' {
			count++
		}
	}
	if count != 1 {
		return 0, false
	}
	return after, true
}

func localStart(text string, pos int) (int, bool) {
	if end, ok := bracketStart(text, pos); ok {
		return end, true
	}
	return dotOrDashStart(text, pos)
}

func fullPhoneStart(text string, pos int) (int, bool) {
	if end, ok := trunkOrInternational(text, pos); ok {
		// Optionally followed by a separator + local start; if that combination
		// does not fully match, keep just the prefix (nom opt backtracks).
		if sep, ok := sectionSep(text, end); ok {
			if local, ok := localStart(text, sep); ok {
				return local, true
			}
		}
		return end, true
	}
	return localStart(text, pos)
}

// genericChunk matches an optional leading separator, 1-10 digits, and an
// optional trailing separator.
func genericChunk(text string, pos int) (int, bool) {
	start := pos
	if s, ok := sectionSep(text, pos); ok {
		start = s
	}
	end, ok := limitedDigits(text, start, 1, 10)
	if !ok {
		return 0, false
	}
	if s, ok := sectionSep(text, end); ok {
		return s, true
	}
	return end, true
}

func parsePhoneNumber(text string, pos int) (int, bool) {
	end, ok := fullPhoneStart(text, pos)
	if !ok {
		return 0, false
	}
	end, ok = genericChunk(text, end)
	if !ok {
		return 0, false
	}
	// Up to four further groups.
	for range 4 {
		nxt, ok := genericChunk(text, end)
		if !ok {
			break
		}
		end = nxt
	}
	return end, true
}

// isFullNanp reports whether candidate is a bare 10-digit NANP number — area
// code, exchange, then four line digits — written with no separators.
func isFullNanp(candidate string) bool {
	end, ok := nxxSection(candidate, 0)
	if !ok {
		return false
	}
	end, ok = nxxSection(candidate, end)
	if !ok {
		return false
	}
	end, ok = takeAndVerify(candidate, end, 4, isDigit)
	if !ok {
		return false
	}
	return end == len(candidate)
}

// isPhoneNumber reports whether candidate is a valid phone number (whole-string
// match). Ported from is_phone_number in arcjet-analyze so the Rampart backend
// and the default (WASM) backend agree on what counts as a phone number.
func isPhoneNumber(candidate string) bool {
	if end, ok := parsePhoneNumber(candidate, 0); ok && end == len(candidate) {
		return true
	}
	return isFullNanp(candidate)
}

// PhoneRecognizer is the phone number recognizer. It finds candidate runs and
// keeps only those that validate as a phone number via isPhoneNumber, matching
// the default backend's rules.
func PhoneRecognizer(value string) []DetectedSpan {
	var result []DetectedSpan
	for _, m := range phoneCandidatePattern.FindAllStringIndex(value, -1) {
		start, end := m[0], m[1]
		// Trim to a tight span: drop leading chars that cannot start a number
		// and trailing separators/whitespace the greedy run absorbed.
		for start < end && !isPhoneLeadByte(value[start]) {
			start++
		}
		for end > start && !isPhoneTailByte(value[end-1]) {
			end--
		}
		if start < end && isPhoneNumber(value[start:end]) {
			result = append(result, DetectedSpan{Start: start, End: end, Type: arcjet.SensitiveInfoPhoneNumber})
		}
	}
	return result
}

// isPhoneLeadByte reports whether b may start a phone span ("0123456789+(").
func isPhoneLeadByte(b byte) bool {
	return isDigit(b) || b == '+' || b == '('
}

// isPhoneTailByte reports whether b may end a phone span ("0123456789)").
func isPhoneTailByte(b byte) bool {
	return isDigit(b) || b == ')'
}

// CreditCardRecognizer is the credit/debit card recognizer, validated with the
// Luhn checksum.
func CreditCardRecognizer(value string) []DetectedSpan {
	var result []DetectedSpan
	for _, span := range matchAll(value, creditCardPattern, arcjet.SensitiveInfoCreditCardNumber) {
		digits := cardSepPattern.ReplaceAllString(value[span.Start:span.End], "")
		if len(digits) >= 13 && len(digits) <= 19 && luhn(digits) {
			result = append(result, span)
		}
	}
	return result
}

// DefaultRecognizers is the default set of deterministic recognizers, ordered
// most-specific first. Overlap resolution happens later in the backend (longer
// spans win; equal-length ties keep the earlier-listed recognizer), so this
// order only breaks ties - for example a Luhn-valid card over the looser phone
// matcher on the same text.
var DefaultRecognizers = []Recognizer{
	CreditCardRecognizer,
	SSNRecognizer,
	EmailRecognizer,
	URLRecognizer,
	IPAddressRecognizer,
	PhoneRecognizer,
}

// RunRecognizers runs a list of recognizers over value and collects every span,
// in recognizer order.
func RunRecognizers(value string, recognizers []Recognizer) []DetectedSpan {
	var spans []DetectedSpan
	for _, recognizer := range recognizers {
		spans = append(spans, recognizer(value)...)
	}
	return spans
}
