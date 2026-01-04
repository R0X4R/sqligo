package scripts

import (
	"regexp"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type VersionedMoreKeywords struct{}

func (v VersionedMoreKeywords) Name() string {
	return "versionedmorekeywords"
}

func (v VersionedMoreKeywords) Description() string {
	return "Encloses each keyword with MySQL versioned comment (extended list)"
}

func (v VersionedMoreKeywords) Apply(payload string) string {
	keywords := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "WHERE", "FROM", "AND", "OR",
		"CONCAT", "SUBSTRING", "MID", "CHAR", "ASCII", "ORD", "LENGTH", "COUNT",
		"DATABASE", "USER", "VERSION", "TABLE", "COLUMN", "SCHEMA",
	}
	result := payload

	for _, keyword := range keywords {
		re := regexp.MustCompile(`(?i)\b` + keyword + `\b`)
		result = re.ReplaceAllStringFunc(result, func(match string) string {
			return "/*!50000" + match + "*/"
		})
	}

	return result
}

func init() {
	tamper.Register(VersionedMoreKeywords{})
}
