package scripts

import (
	"strings"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Space2MySQLDash struct{}

func (s Space2MySQLDash) Name() string {
	return "space2mysqldash"
}

func (s Space2MySQLDash) Description() string {
	return "Replaces space character (' ') with a dash comment ('--') followed by a new line ('\\n')"
}

func (s Space2MySQLDash) Apply(payload string) string {
	return strings.ReplaceAll(payload, " ", "--\n")
}

func init() {
	tamper.Register(Space2MySQLDash{})
}
