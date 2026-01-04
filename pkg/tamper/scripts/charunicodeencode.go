package scripts

import (
	"fmt"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type CharUnicodeEncode struct{}

func (c CharUnicodeEncode) Name() string {
	return "charunicodeencode"
}

func (c CharUnicodeEncode) Description() string {
	return "Unicode-encodes non-encoded characters in a given payload (e.g., SELECT -> \\u0053\\u0045\\u004C\\u0045\\u0043\\u0054)"
}

func (c CharUnicodeEncode) Apply(payload string) string {
	result := ""
	for _, char := range payload {
		result += fmt.Sprintf("\\u%04X", char)
	}
	return result
}

func init() {
	tamper.Register(CharUnicodeEncode{})
}
