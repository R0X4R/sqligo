package scripts

import (
	"regexp"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Between struct{}

func (b Between) Name() string {
	return "between"
}

func (b Between) Description() string {
	return "Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #'"
}

func (b Between) Apply(payload string) string {
	// Replace patterns like "X>Y" with "X NOT BETWEEN 0 AND Y"
	re := regexp.MustCompile(`(\w+)\s*>\s*(\w+)`)
	return re.ReplaceAllString(payload, "$1 NOT BETWEEN 0 AND $2")
}

func init() {
	tamper.Register(Between{})
}
