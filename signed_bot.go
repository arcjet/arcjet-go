package arcjet

import (
	"slices"
	"strings"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

// These identities and categories mirror the signed operators in the
// well-known-bots catalog. A signature can change a bot's identity even when
// local User-Agent matching would have denied it.
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

func mayBeSignedBot(entity string) bool {
	if strings.HasPrefix(entity, "SIGNED_BOT:") {
		return true
	}
	switch entity {
	case "GOOGLE_AGENT", "CHATGPT_AGENT", "DUCKASSIST_BOT", "BROWSERBASE", "MANUS_BOT":
		return true
	case BotCategoryAI, BotCategoryGoogle, BotCategorySearchEngine, BotCategoryTool:
		return true
	default:
		return false
	}
}

func hasSignatureInput(headers map[string]string) bool {
	for name := range headers {
		if strings.EqualFold(name, "signature-input") {
			return true
		}
	}
	return false
}
