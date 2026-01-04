package scripts

import (
	"regexp"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type EqualToLike struct{}

func (e EqualToLike) Name() string {
	return "equaltolike"
}

func (e EqualToLike) Description() string {
	return "Replaces all occurrences of operator equal ('=') with 'LIKE'"
}

func (e EqualToLike) Apply(payload string) string {
	// Replace = with LIKE, but avoid replacing in already encoded strings
	re := regexp.MustCompile(`\s*=\s*`)
	return re.ReplaceAllString(payload, " LIKE ")
}

func init() {
	tamper.Register(EqualToLike{})
}
