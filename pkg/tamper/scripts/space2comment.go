package scripts

import (
	"strings"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Space2Comment struct{}

func (s Space2Comment) Name() string {
	return "space2comment"
}

func (s Space2Comment) Description() string {
	return "Replaces space character (' ') with comments ('/**/')"
}

func (s Space2Comment) Apply(payload string) string {
	return strings.ReplaceAll(payload, " ", "/**/")
}

func init() {
	tamper.Register(Space2Comment{})
}
