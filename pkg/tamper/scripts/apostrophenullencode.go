package scripts

import (
	"strings"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type ApostropheNullEncode struct{}

func (a ApostropheNullEncode) Name() string {
	return "apostrophenullencode"
}

func (a ApostropheNullEncode) Description() string {
	return "Replaces apostrophe character (') with its UTF-8 full width counterpart along with a NULL byte"
}

func (a ApostropheNullEncode) Apply(payload string) string {
	return strings.ReplaceAll(payload, "'", "%00%27")
}

func init() {
	tamper.Register(ApostropheNullEncode{})
}
