package scripts

import (
	"strings"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Space2Plus struct{}

func (s Space2Plus) Name() string {
	return "space2plus"
}

func (s Space2Plus) Description() string {
	return "Replaces space character (' ') with plus ('+')"
}

func (s Space2Plus) Apply(payload string) string {
	return strings.ReplaceAll(payload, " ", "+")
}

func init() {
	tamper.Register(Space2Plus{})
}
