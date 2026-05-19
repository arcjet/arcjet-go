package arcjet

import (
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

type decisionWire struct {
	ID          string           `json:"id"`
	Conclusion  string           `json:"conclusion"`
	Reason      json.RawMessage  `json:"reason"`
	RuleResults []ruleResultWire `json:"ruleResults"`
	TTL         int              `json:"ttl"`
	IPDetails   IPDetails        `json:"ipDetails"`
}

type ruleResultWire struct {
	RuleID      string          `json:"ruleId"`
	State       string          `json:"state"`
	Conclusion  string          `json:"conclusion"`
	Reason      json.RawMessage `json:"reason"`
	TTL         int             `json:"ttl"`
	Fingerprint string          `json:"fingerprint"`
}

func (d decisionWire) toDecision() Decision {
	results := make([]RuleResult, 0, len(d.RuleResults))
	for _, r := range d.RuleResults {
		results = append(results, RuleResult{
			RuleID:      r.RuleID,
			State:       RuleState(r.State),
			Conclusion:  parseConclusion(r.Conclusion),
			Reason:      parseReason(r.Reason),
			TTL:         r.TTL,
			Fingerprint: r.Fingerprint,
		})
	}
	return Decision{
		ID:         d.ID,
		Conclusion: parseConclusion(d.Conclusion),
		Reason:     parseReason(d.Reason),
		Results:    results,
		TTL:        d.TTL,
		IP:         d.IPDetails,
		Raw:        d.Reason,
	}
}

func decisionFromProto(dec *decidev1.Decision) Decision {
	if dec == nil {
		return Decision{Conclusion: ConclusionError, Reason: Reason{Type: ReasonError, Message: "empty decision response"}}
	}
	data, err := protojson.Marshal(dec)
	if err != nil {
		return Decision{Conclusion: ConclusionError, Reason: Reason{Type: ReasonError, Message: err.Error()}}
	}
	var wire decisionWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return Decision{Conclusion: ConclusionError, Reason: Reason{Type: ReasonError, Message: err.Error()}}
	}
	wire.ID = dec.GetId()
	return wire.toDecision()
}

// parseConclusion normalizes a wire-format conclusion string (Decide or Guard
// prefixed, or bare) to a canonical Conclusion constant.
func parseConclusion(s string) Conclusion {
	switch s {
	case "CONCLUSION_ALLOW", "GUARD_CONCLUSION_ALLOW", "ALLOW":
		return ConclusionAllow
	case "CONCLUSION_DENY", "GUARD_CONCLUSION_DENY", "DENY":
		return ConclusionDeny
	case "CONCLUSION_CHALLENGE", "CHALLENGE":
		return ConclusionChallenge
	case "CONCLUSION_ERROR", "ERROR":
		return ConclusionError
	default:
		return Conclusion(s)
	}
}

// reasonParser decodes one envelope key into a Reason. Each parser owns its
// own concrete type so we don't lose typed reasons through any-interface
// shuffling.
type reasonParser func(json.RawMessage) (Reason, error)

// reasonParsers lists the wire envelope keys parseReason recognizes, in the
// priority order they should be tried. The first matching key wins.
var reasonParsers = []struct {
	key   string
	parse reasonParser
}{
	{"rateLimit", func(v json.RawMessage) (Reason, error) {
		var r RateLimitReason
		err := json.Unmarshal(v, &r)
		return Reason{Type: ReasonRateLimit, RateLimit: &r}, err
	}},
	{"botV2", func(v json.RawMessage) (Reason, error) {
		var r BotReason
		err := json.Unmarshal(v, &r)
		return Reason{Type: ReasonBot, Bot: &r}, err
	}},
	{"bot", func(v json.RawMessage) (Reason, error) {
		var r BotReason
		err := json.Unmarshal(v, &r)
		return Reason{Type: ReasonBot, Bot: &r}, err
	}},
	{"shield", func(v json.RawMessage) (Reason, error) {
		var r ShieldReason
		err := json.Unmarshal(v, &r)
		return Reason{Type: ReasonShield, Shield: &r}, err
	}},
	{"email", func(v json.RawMessage) (Reason, error) {
		var r EmailReason
		err := json.Unmarshal(v, &r)
		return Reason{Type: ReasonEmail, Email: &r}, err
	}},
	{"sensitiveInfo", func(v json.RawMessage) (Reason, error) {
		var r SensitiveInfoReason
		err := json.Unmarshal(v, &r)
		return Reason{Type: ReasonSensitiveInfo, SensitiveInfo: &r}, err
	}},
	{"promptInjection", func(v json.RawMessage) (Reason, error) {
		var r PromptInjectionReason
		err := json.Unmarshal(v, &r)
		return Reason{Type: ReasonPromptInjection, PromptInjection: &r}, err
	}},
	{"filter", func(v json.RawMessage) (Reason, error) {
		var r FilterReason
		err := json.Unmarshal(v, &r)
		return Reason{Type: ReasonFilter, Filter: &r}, err
	}},
	{"error", func(v json.RawMessage) (Reason, error) {
		var e ArcjetError
		err := json.Unmarshal(v, &e)
		return Reason{Type: ReasonError, Message: e.Message}, err
	}},
}

func parseReason(raw json.RawMessage) Reason {
	if len(raw) == 0 || string(raw) == "null" {
		return Reason{}
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Reason{Type: ReasonError, Message: err.Error()}
	}
	for _, p := range reasonParsers {
		v, ok := envelope[p.key]
		if !ok {
			continue
		}
		reason, err := p.parse(v)
		if err != nil {
			return Reason{Type: ReasonError, Message: p.key + ": " + err.Error()}
		}
		return reason
	}
	return Reason{}
}
