package arcjet

import (
	"slices"
	"strings"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

// botRulesMayVerifySignature reports whether any bot rule names a bot or
// category that Arcjet Cloud may identify by a Web Bot Auth signature. A
// signature can change a bot's identity even when local User-Agent matching
// would have denied it.
func botRulesMayVerifySignature(rules []*decidev1.Rule) bool {
	for _, rule := range rules {
		bot := rule.GetBotV2()
		if bot == nil {
			continue
		}
		if slices.ContainsFunc(bot.GetAllow(), mayBeSignedBot) ||
			slices.ContainsFunc(bot.GetDeny(), mayBeSignedBot) {
			return true
		}
	}
	return false
}

// mayBeSignedBot reports whether entity is a signed bot directory, a bot
// that signs requests with Web Bot Auth, or a category that contains one.
// The bots and categories come from the generated signedBotEntities.
func mayBeSignedBot(entity string) bool {
	if strings.HasPrefix(entity, "SIGNED_BOT:") {
		return true
	}
	_, ok := signedBotEntities[entity]
	return ok
}

func hasSignatureInput(headers map[string]string) bool {
	for name := range headers {
		if strings.EqualFold(name, "signature-input") {
			return true
		}
	}
	return false
}
