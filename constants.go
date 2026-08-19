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
	BotCategoryApple        = "CATEGORY:APPLE"
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
	BotCategoryWebhook      = "CATEGORY:WEBHOOK"
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
// The first four are detected by the bundled WebAssembly analyzer. The
// remainder require a backend that supports them (see [SensitiveInfoBackend]
// and the github.com/arcjet/arcjet-go/sensitiveinfo/rampart module) or a custom
// [SensitiveInfoDetect] callback; listing one without either is a
// configuration error.
const (
	SensitiveInfoEmail            EntityType = "EMAIL"
	SensitiveInfoPhoneNumber      EntityType = "PHONE_NUMBER"
	SensitiveInfoIPAddress        EntityType = "IP_ADDRESS"
	SensitiveInfoCreditCardNumber EntityType = "CREDIT_CARD_NUMBER"

	SensitiveInfoURL              EntityType = "URL"
	SensitiveInfoSSN              EntityType = "SSN"
	SensitiveInfoGivenName        EntityType = "GIVEN_NAME"
	SensitiveInfoSurname          EntityType = "SURNAME"
	SensitiveInfoTaxID            EntityType = "TAX_ID"
	SensitiveInfoBankAccount      EntityType = "BANK_ACCOUNT"
	SensitiveInfoRoutingNumber    EntityType = "ROUTING_NUMBER"
	SensitiveInfoGovernmentID     EntityType = "GOVERNMENT_ID"
	SensitiveInfoPassport         EntityType = "PASSPORT"
	SensitiveInfoDriversLicense   EntityType = "DRIVERS_LICENSE"
	SensitiveInfoBuildingNumber   EntityType = "BUILDING_NUMBER"
	SensitiveInfoStreetName       EntityType = "STREET_NAME"
	SensitiveInfoSecondaryAddress EntityType = "SECONDARY_ADDRESS"
	SensitiveInfoCity             EntityType = "CITY"
	SensitiveInfoState            EntityType = "STATE"
	SensitiveInfoZipCode          EntityType = "ZIP_CODE"
)
