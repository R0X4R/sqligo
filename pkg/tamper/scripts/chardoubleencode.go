package scripts

import (
	"fmt"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type CharDoubleEncode struct{}

func (c CharDoubleEncode) Name() string {
	return "chardoubleencode"
}

func (c CharDoubleEncode) Description() string {
	return "Double URL-encodes all characters in a given payload"
}

func (c CharDoubleEncode) Apply(payload string) string {
	result := ""
	for _, char := range payload {
		// First encoding
		encoded := fmt.Sprintf("%%%02X", char)
		// Second encoding
		for _, e := range encoded {
			result += fmt.Sprintf("%%%02X", e)
		}
	}
	return result
}

func init() {
	tamper.Register(CharDoubleEncode{})
}
