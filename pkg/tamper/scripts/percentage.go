package scripts

import (
	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Percentage struct{}

func (p Percentage) Name() string {
	return "percentage"
}

func (p Percentage) Description() string {
	return "Adds a percentage sign ('%') infront of each character (e.g., SELECT -> %S%E%L%E%C%T)"
}

func (p Percentage) Apply(payload string) string {
	result := ""
	for _, char := range payload {
		result += "%" + string(char)
	}
	return result
}

func init() {
	tamper.Register(Percentage{})
}
