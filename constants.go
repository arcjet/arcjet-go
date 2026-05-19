package arcjet

// Bot category identifiers for use with BotOptions.Allow and BotOptions.Deny.
//
// Categories group well-known bots so a single entry covers many user agents.
// Pass these alongside any specific bot identifiers from
// https://arcjet.com/bot-list. Strings are still accepted; these constants
// exist for autocomplete and to catch typos at compile time.
const (
	BotCategoryAcademic     = "CATEGORY:ACADEMIC"
	BotCategoryAdvertising  = "CATEGORY:ADVERTISING"
	BotCategoryAI           = "CATEGORY:AI"
	BotCategoryAmazon       = "CATEGORY:AMAZON"
	BotCategoryArchive      = "CATEGORY:ARCHIVE"
	BotCategoryBotnet       = "CATEGORY:BOTNET"
	BotCategoryFeedFetcher  = "CATEGORY:FEEDFETCHER"
	BotCategoryGoogle       = "CATEGORY:GOOGLE"
	BotCategoryMeta         = "CATEGORY:META"
	BotCategoryMicrosoft    = "CATEGORY:MICROSOFT"
	BotCategoryMonitor      = "CATEGORY:MONITOR"
	BotCategoryOptimizer    = "CATEGORY:OPTIMIZER"
	BotCategoryPreview      = "CATEGORY:PREVIEW"
	BotCategoryProgrammatic = "CATEGORY:PROGRAMMATIC"
	BotCategorySearchEngine = "CATEGORY:SEARCH_ENGINE"
	BotCategorySlack        = "CATEGORY:SLACK"
	BotCategorySocial       = "CATEGORY:SOCIAL"
	BotCategoryTool         = "CATEGORY:TOOL"
	BotCategoryUnknown      = "CATEGORY:UNKNOWN"
	BotCategoryVercel       = "CATEGORY:VERCEL"
	BotCategoryYahoo        = "CATEGORY:YAHOO"
)

// Email type identifiers for use with EmailOptions.Allow and EmailOptions.Deny.
const (
	EmailTypeDisposable  EmailType = "DISPOSABLE"
	EmailTypeFree        EmailType = "FREE"
	EmailTypeInvalid     EmailType = "INVALID"
	EmailTypeNoMXRecords EmailType = "NO_MX_RECORDS"
	EmailTypeNoGravatar  EmailType = "NO_GRAVATAR"
)

// Sensitive information entity type identifiers for use with
// SensitiveInfoOptions.Allow, SensitiveInfoOptions.Deny,
// GuardSensitiveInfoOptions.Allow, and GuardSensitiveInfoOptions.Deny.
const (
	SensitiveInfoEmail            EntityType = "EMAIL"
	SensitiveInfoPhoneNumber      EntityType = "PHONE_NUMBER"
	SensitiveInfoIPAddress        EntityType = "IP_ADDRESS"
	SensitiveInfoCreditCardNumber EntityType = "CREDIT_CARD_NUMBER"
)
