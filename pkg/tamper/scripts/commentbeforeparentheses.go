package scripts

import (
	"strings"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type CommentBeforeParentheses struct{}

func (c CommentBeforeParentheses) Name() string {
	return "commentbeforeparentheses"
}

func (c CommentBeforeParentheses) Description() string {
	return "Prepends (inline) comment before parentheses (e.g., '(' -> '/**/('))"
}

func (c CommentBeforeParentheses) Apply(payload string) string {
	return strings.ReplaceAll(payload, "(", "/**/(")
}

func init() {
	tamper.Register(CommentBeforeParentheses{})
}
