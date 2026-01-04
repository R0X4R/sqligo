package scripts

import (
	"encoding/base64"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Base64Encode struct{}

func (b Base64Encode) Name() string {
	return "base64encode"
}

func (b Base64Encode) Description() string {
	return "Base64 encodes the entire payload"
}

func (b Base64Encode) Apply(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

func init() {
	tamper.Register(Base64Encode{})
}
