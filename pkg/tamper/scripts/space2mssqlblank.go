package scripts

import (
	"math/rand"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Space2MSSQLBlank struct{}

func (s Space2MSSQLBlank) Name() string {
	return "space2mssqlblank"
}

func (s Space2MSSQLBlank) Description() string {
	return "Replaces space character (' ') with a random blank character from a valid set of alternate characters for MSSQL"
}

func (s Space2MSSQLBlank) Apply(payload string) string {
	// MSSQL valid blank characters
	blanks := []string{"%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08", "%09", "%0B", "%0C", "%0D", "%0E", "%0F"}

	result := ""
	for _, char := range payload {
		if char == ' ' {
			result += blanks[rand.Intn(len(blanks))]
		} else {
			result += string(char)
		}
	}
	return result
}

func init() {
	tamper.Register(Space2MSSQLBlank{})
}
