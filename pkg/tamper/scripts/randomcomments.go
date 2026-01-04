package scripts

import (
	"math/rand"
	"strings"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type RandomComments struct{}

func (r RandomComments) Name() string {
	return "randomcomments"
}

func (r RandomComments) Description() string {
	return "Add random inline comments to SQL keywords (e.g., SELECT -> SE/**/LECT)"
}

func (r RandomComments) Apply(payload string) string {
	keywords := []string{"SELECT", "FROM", "WHERE", "AND", "OR", "UNION", "INSERT", "UPDATE", "DELETE"}
	result := payload

	for _, keyword := range keywords {
		if strings.Contains(strings.ToUpper(result), keyword) {
			// Insert /**/ at random position within keyword
			if len(keyword) > 2 {
				pos := rand.Intn(len(keyword)-1) + 1
				commented := keyword[:pos] + "/**/" + keyword[pos:]
				result = strings.ReplaceAll(result, keyword, commented)
				result = strings.ReplaceAll(result, strings.ToLower(keyword), strings.ToLower(commented))
			}
		}
	}

	return result
}

func init() {
	tamper.Register(RandomComments{})
}
