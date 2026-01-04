package scripts

import (
	"regexp"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Greatest struct{}

func (g Greatest) Name() string {
	return "greatest"
}

func (g Greatest) Description() string {
	return "Replaces greater than operator ('>') with 'GREATEST' counterpart"
}

func (g Greatest) Apply(payload string) string {
	// Replace patterns like "X>Y" with "GREATEST(X,Y+1)=X"
	re := regexp.MustCompile(`(\w+)\s*>\s*(\w+)`)
	return re.ReplaceAllString(payload, "GREATEST($1,$2+1)=$1")
}

func init() {
	tamper.Register(Greatest{})
}
