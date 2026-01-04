package scripts

import (
	"math/rand"
	"strings"
	"unicode"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type RandomCase struct{}

func (r RandomCase) Name() string {
	return "randomcase"
}

func (r RandomCase) Description() string {
	return "Replaces each keyword character with random case value"
}

func (r RandomCase) Apply(payload string) string {
	result := strings.Builder{}
	for _, char := range payload {
		if unicode.IsLetter(char) {
			if rand.Intn(2) == 0 {
				result.WriteRune(unicode.ToUpper(char))
			} else {
				result.WriteRune(unicode.ToLower(char))
			}
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

func init() {
	tamper.Register(RandomCase{})
}
