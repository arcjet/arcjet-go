package arcjet

import (
	"slices"
	"strings"

	decidev1 "github.com/arcjet/arcjet-go/internal/proto/decide/v1alpha1"
)

// Keep these identities and their containing categories in sync with
// verification[type=web-bot-auth] entries in the source catalog:
// https://github.com/arcjet/well-known-bots/blob/main/well-known-bots.json.
// A signature can change a bot's identity even when local User-Agent matching
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

func mayBeSignedBot(entity string) bool {
	if strings.HasPrefix(entity, "SIGNED_BOT:") {
		return true
	}
	switch entity {
	case "GOOGLE_AGENT", "CHATGPT_AGENT", "DUCKASSIST_BOT", "BROWSERBASE", "MANUS_BOT",
		"YOU_CRAWLER", "EXA_SEARCHBOT", "CONTEXT7_CRAWLER", "SHOPIFY_CLOUDSURF",
		"KERNEL_AGENT", "KERNEL_SEARCH", "OSANO_BOT", "CLOUDFLARE_BROWSER_RUN",
		"LANE_AGENT":
		return true
	case BotCategoryAI, BotCategoryGoogle, BotCategorySearchEngine, BotCategoryTool,
		BotCategoryMonitor:
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
