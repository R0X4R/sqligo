package scripts

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Hex2Char struct{}

func (h Hex2Char) Name() string {
	return "hex2char"
}

func (h Hex2Char) Description() string {
	return "Replaces each (MySQL) 0x<hex> encoded string with equivalent CHAR() (e.g., 0x414243 -> CHAR(65,66,67))"
}

func (h Hex2Char) Apply(payload string) string {
	// Find all 0x[hexdigits] patterns
	re := regexp.MustCompile(`0x([0-9a-fA-F]+)`)

	return re.ReplaceAllStringFunc(payload, func(match string) string {
		hexStr := match[2:] // Remove "0x" prefix

		// Convert hex string to decimal values
		chars := []string{}
		for i := 0; i < len(hexStr); i += 2 {
			if i+1 < len(hexStr) {
				hexByte := hexStr[i : i+2]
				if val, err := strconv.ParseInt(hexByte, 16, 64); err == nil {
					chars = append(chars, fmt.Sprintf("%d", val))
				}
			}
		}

		if len(chars) > 0 {
			return fmt.Sprintf("CHAR(%s)", string(chars[0]))
		}
		return match
	})
}

func init() {
	tamper.Register(Hex2Char{})
}
