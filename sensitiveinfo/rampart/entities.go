package rampart

import (
	"strings"

	arcjet "github.com/arcjet/arcjet-go"
)

// id2label is the model's label map, baked in from the Rampart config.json
// (id2label). Index by label id (the argmax over the model's 35 output logits).
var id2label = [...]string{
	"O",
	"B-GIVEN_NAME", "I-GIVEN_NAME",
	"B-SURNAME", "I-SURNAME",
	"B-EMAIL", "I-EMAIL",
	"B-PHONE", "I-PHONE",
	"B-URL", "I-URL",
	"B-TAX_ID", "I-TAX_ID",
	"B-BANK_ACCOUNT", "I-BANK_ACCOUNT",
	"B-ROUTING_NUMBER", "I-ROUTING_NUMBER",
	"B-GOVERNMENT_ID", "I-GOVERNMENT_ID",
	"B-PASSPORT", "I-PASSPORT",
	"B-DRIVERS_LICENSE", "I-DRIVERS_LICENSE",
	"B-BUILDING_NUMBER", "I-BUILDING_NUMBER",
	"B-STREET_NAME", "I-STREET_NAME",
	"B-SECONDARY_ADDRESS", "I-SECONDARY_ADDRESS",
	"B-CITY", "I-CITY",
	"B-STATE", "I-STATE",
	"B-ZIP_CODE", "I-ZIP_CODE",
}

// numLabels is the model's output dimension.
const numLabels = len(id2label)

// labelAliases aligns the model's and recognizers' label naming to the entity
// type strings Arcjet uses elsewhere, so (for example) deny=[PHONE_NUMBER]
// works regardless of backend. Keys are upper-cased and BIO-prefix-stripped
// before lookup. Ported from arcjet-py's _entities._LABEL_ALIASES.
var labelAliases = map[string]arcjet.EntityType{
	"EMAIL":              arcjet.SensitiveInfoEmail,
	"EMAIL_ADDRESS":      arcjet.SensitiveInfoEmail,
	"PHONE":              arcjet.SensitiveInfoPhoneNumber,
	"PHONE_NUMBER":       arcjet.SensitiveInfoPhoneNumber,
	"IP":                 arcjet.SensitiveInfoIPAddress,
	"IP_ADDRESS":         arcjet.SensitiveInfoIPAddress,
	"CREDIT_CARD":        arcjet.SensitiveInfoCreditCardNumber,
	"CREDIT_CARD_NUMBER": arcjet.SensitiveInfoCreditCardNumber,
	"URL":                arcjet.SensitiveInfoURL,
	"SSN":                arcjet.SensitiveInfoSSN,
	"GIVEN_NAME":         arcjet.SensitiveInfoGivenName,
	"SURNAME":            arcjet.SensitiveInfoSurname,
	"TAX_ID":             arcjet.SensitiveInfoTaxID,
	"BANK_ACCOUNT":       arcjet.SensitiveInfoBankAccount,
	"ROUTING_NUMBER":     arcjet.SensitiveInfoRoutingNumber,
	"GOVERNMENT_ID":      arcjet.SensitiveInfoGovernmentID,
	"PASSPORT":           arcjet.SensitiveInfoPassport,
	"DRIVERS_LICENSE":    arcjet.SensitiveInfoDriversLicense,
	"BUILDING_NUMBER":    arcjet.SensitiveInfoBuildingNumber,
	"STREET_NAME":        arcjet.SensitiveInfoStreetName,
	"SECONDARY_ADDRESS":  arcjet.SensitiveInfoSecondaryAddress,
	"CITY":               arcjet.SensitiveInfoCity,
	"STATE":              arcjet.SensitiveInfoState,
	"ZIP_CODE":           arcjet.SensitiveInfoZipCode,
	"ZIP":                arcjet.SensitiveInfoZipCode,
	"POSTAL_CODE":        arcjet.SensitiveInfoZipCode,
}

// rampartEntities lists every entity type this backend can emit (from the NER
// model and the deterministic recognizers combined).
var rampartEntities = []arcjet.EntityType{
	arcjet.SensitiveInfoEmail,
	arcjet.SensitiveInfoPhoneNumber,
	arcjet.SensitiveInfoIPAddress,
	arcjet.SensitiveInfoCreditCardNumber,
	arcjet.SensitiveInfoURL,
	arcjet.SensitiveInfoSSN,
	arcjet.SensitiveInfoGivenName,
	arcjet.SensitiveInfoSurname,
	arcjet.SensitiveInfoTaxID,
	arcjet.SensitiveInfoBankAccount,
	arcjet.SensitiveInfoRoutingNumber,
	arcjet.SensitiveInfoGovernmentID,
	arcjet.SensitiveInfoPassport,
	arcjet.SensitiveInfoDriversLicense,
	arcjet.SensitiveInfoBuildingNumber,
	arcjet.SensitiveInfoStreetName,
	arcjet.SensitiveInfoSecondaryAddress,
	arcjet.SensitiveInfoCity,
	arcjet.SensitiveInfoState,
	arcjet.SensitiveInfoZipCode,
}

// normalizeLabel maps a raw model or recognizer label (such as "B-GIVEN_NAME"
// or "phone") to an Arcjet entity type. ok is false for the outside label "O",
// the empty string, or any label with no alias. Ported from arcjet-py's
// _entities.normalize_label.
func normalizeLabel(label string) (arcjet.EntityType, bool) {
	stripped := strings.ToUpper(stripBIOPrefix(label))
	if stripped == "O" || stripped == "" {
		return "", false
	}
	t, ok := labelAliases[stripped]
	return t, ok
}

// stripBIOPrefix removes a leading BIO(-like) tag prefix — one of b/i/l/u/e/s
// followed by "-", case-insensitive — matching the _BIO_PREFIX regex
// `^[biluest]-` used by the reference implementation.
func stripBIOPrefix(label string) string {
	if len(label) >= 2 && label[1] == '-' {
		switch label[0] {
		case 'b', 'i', 'l', 'u', 'e', 's', 't',
			'B', 'I', 'L', 'U', 'E', 'S', 'T':
			return label[2:]
		}
	}
	return label
}
