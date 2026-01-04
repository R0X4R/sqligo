package scripts

import (
	"regexp"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type HalfVersionedMoreKeywords struct{}

func (h HalfVersionedMoreKeywords) Name() string {
	return "halfversionedmorekeywords"
}

func (h HalfVersionedMoreKeywords) Description() string {
	return "Encloses each keyword with MySQL half-versioned comment (/*!0keyword*/)"
}

func (h HalfVersionedMoreKeywords) Apply(payload string) string {
	keywords := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "WHERE", "FROM", "AND", "OR",
		"CONCAT", "SUBSTRING", "DATABASE", "USER", "VERSION",
	}
	result := payload

	for _, keyword := range keywords {
		re := regexp.MustCompile(`(?i)\b` + keyword + `\b`)
		result = re.ReplaceAllStringFunc(result, func(match string) string {
			return "/*!0" + match + "*/"
		})
	}

	return result
}

func init() {
	tamper.Register(HalfVersionedMoreKeywords{})
}
