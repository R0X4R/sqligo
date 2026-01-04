package scripts

import (
	"strings"

	"github.com/R0X4R/sqligo/pkg/tamper"
)

type UnionAllToUnion struct{}

func (u UnionAllToUnion) Name() string {
	return "unionalltounion"
}

func (u UnionAllToUnion) Description() string {
	return "Replaces instances of UNION ALL SELECT with UNION SELECT"
}

func (u UnionAllToUnion) Apply(payload string) string {
	// Case-insensitive replacement
	result := payload
	result = strings.ReplaceAll(result, "UNION ALL SELECT", "UNION SELECT")
	result = strings.ReplaceAll(result, "union all select", "union select")
	result = strings.ReplaceAll(result, "Union All Select", "Union Select")
	return result
}

func init() {
	tamper.Register(UnionAllToUnion{})
}
