package utils

import (
	"regexp"
)

// ReplaceXmlValue replaces the text content of a generic XML tag.
// Regex-based for flexibility with malformed/fragmented input.
func ReplaceXmlValue(data, tag, newValue string) string {
	// Tag should be the node name.
	// data: <root><nr>1</nr></root>
	// Replace 1 with 1'
	// Regex: <tag[^>]*>([^<]*)</tag>

	safeTag := regexp.QuoteMeta(tag)

	// Pattern: (<tag[^>]*>)([^<]*)(</tag>)
	re := regexp.MustCompile(`(<` + safeTag + `[^>]*>)([^<]*)(</` + safeTag + `>)`)

	// We replace the middle group with newValue
	return re.ReplaceAllString(data, "${1}"+newValue+"${3}")
}
