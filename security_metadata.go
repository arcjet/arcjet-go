package arcjet

// SecurityMetadata is the shared vocabulary for describing who is acting,
// on what, and how reversible the effect is. Metadata projects it to the
// keys the JavaScript and Python helpers use, omitting empty fields.
type SecurityMetadata struct {
	// User is whose authority the action runs under: an opaque ID, not PII.
	User string
	// Agent is the type or identity of the AI actor.
	Agent string
	// Workflow is the process this action belongs to.
	Workflow string
	// DataClass is the data sensitivity level, for example "confidential".
	DataClass string
	// Destination is where effects are sent, for example "email".
	Destination string
	// Reversibility is "reversible", "compensable", or "irreversible".
	Reversibility string
	// Resource is what is acted on, for example "order:12345".
	Resource string
}

// Metadata returns the non-empty fields as Metadata under the shared keys.
func (m SecurityMetadata) Metadata() Metadata {
	fields := [...]struct{ key, value string }{
		{"user", m.User},
		{"agent", m.Agent},
		{"workflow", m.Workflow},
		{"dataClass", m.DataClass},
		{"destination", m.Destination},
		{"reversibility", m.Reversibility},
		{"resource", m.Resource},
	}
	md := Metadata{}
	for _, f := range fields {
		if f.value != "" {
			md[f.key] = f.value
		}
	}
	return md
}
