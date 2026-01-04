package scripts

import (
	"github.com/R0X4R/sqligo/pkg/tamper"
)

type AppendNullByte struct{}

func (a AppendNullByte) Name() string {
	return "appendnullbyte"
}

func (a AppendNullByte) Description() string {
	return "Appends encoded NULL byte character at the end of payload"
}

func (a AppendNullByte) Apply(payload string) string {
	return payload + "%00"
}

func init() {
	tamper.Register(AppendNullByte{})
}
