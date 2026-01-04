package scripts

import (
	"fmt"
	"unicode"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type CharEncode struct{}

func (c CharEncode) Name() string {
	return "charencode"
}

func (c CharEncode) Description() string {
	return "URL encodes all characters in a given payload (not processing already encoded)"
}

func (c CharEncode) Apply(payload string) string {
	result := ""
	for _, char := range payload {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			result += string(char)
		} else {
			result += fmt.Sprintf("%%%02X", char)
		}
	}
	return result
}

func init() {
	tamper.Register(CharEncode{})
}
