package scripts

import (
	"fmt"
	"math/rand"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type Space2MoreHash struct{}

func (s Space2MoreHash) Name() string {
	return "space2morehash"
}

func (s Space2MoreHash) Description() string {
	return "Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\\n')"
}

func (s Space2MoreHash) Apply(payload string) string {
	result := ""
	for _, char := range payload {
		if char == ' ' {
			randomStr := fmt.Sprintf("%d", rand.Intn(9999))
			result += "#" + randomStr + "\n"
		} else {
			result += string(char)
		}
	}
	return result
}

func init() {
	tamper.Register(Space2MoreHash{})
}
