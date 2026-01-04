package scripts

import (
	"regexp"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type VersionedKeywords struct{}

func (v VersionedKeywords) Name() string {
	return "versionedkeywords"
}

func (v VersionedKeywords) Description() string {
	return "Encloses each non-function keyword with MySQL versioned comment (e.g., SELECT -> /*!50000SELECT*/)"
}

func (v VersionedKeywords) Apply(payload string) string {
	keywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "WHERE", "FROM", "AND", "OR"}
	result := payload

	for _, keyword := range keywords {
		// Case-insensitive replacement
		re := regexp.MustCompile(`(?i)\b` + keyword + `\b`)
		result = re.ReplaceAllStringFunc(result, func(match string) string {
			return "/*!50000" + match + "*/"
		})
	}

	return result
}

func init() {
	tamper.Register(VersionedKeywords{})
}
