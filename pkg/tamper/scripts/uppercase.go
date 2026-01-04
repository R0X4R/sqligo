package scripts

import (
	"strings"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Uppercase struct{}

func (u Uppercase) Name() string {
	return "uppercase"
}

func (u Uppercase) Description() string {
	return "Replaces each keyword character with upper case value"
}

func (u Uppercase) Apply(payload string) string {
	return strings.ToUpper(payload)
}

func init() {
	tamper.Register(Uppercase{})
}
