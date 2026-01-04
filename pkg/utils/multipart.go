package utils

import (
	"regexp"
)

// ReplaceMultipartValue replaces the value of a specific form field in a Multipart body.
// It uses regex to locate the field by name and replaces content until the next boundary.
func ReplaceMultipartValue(data, name, newValue string) string {
	// Pattern to find:
	// name="NAME" (followed by optional filename/etc) then \r\n\r\n
	// Standard headers: Content-Disposition: form-data; name="field"
	// Then double CRLF.
	// Then Value.
	// Then CRLF + Boundary (starts with --)

	// We need to capture:
	// 1. The start up to the value (Prefix)
	// 2. The value (to replace)
	// 3. The rest (Suffix)

	// Since regex in Go doesn't support lookaround perfectly, we use submatches.
	// `(?s)` enables dot matching newline.
	// Note: Multipart headers line usually ends with \r\n or \n.
	// We look for `name="NAME"`

	safeName := regexp.QuoteMeta(name)
	// Match headers causing `name="NAME"`
	// Then `\r\n\r\n` (or `\n\n`) marking start of value.
	// Then content until `\r\n--` or `\n--` (next boundary).

	// Pattern:
	// (Content-Disposition:.*?name="NAME".*?(?:\r\n|\n){2})(.*?)(?:\r\n--|\n--)
	// But we need to keep the "next boundary" marker!

	// Actually, simpler:
	// Split by Name pattern.

	re := regexp.MustCompile(`(?i)(Content-Disposition:.*?name="` + safeName + `".*?(\r\n|\n){2})(.*?)(\r\n-{2}|\n-{2})`)

	// ReplaceAllStringFunc or ReplaceAllString
	// We want to replace the middle group.

	return re.ReplaceAllStringFunc(data, func(match string) string {
		// Find submatches again (inefficient but safe) or just split
		// match contains: Header + Value + NextBoundaryStart

		// Find split point between Header and Value
		// It's the double newline.

		// Find split point between Value and Boundary
		// It's the last newline before --

		// Let's use FindStringSubmatch
		parts := re.FindStringSubmatch(match)
		if len(parts) >= 4 {
			header := parts[1] // includes \r\n\r\n
			// value := parts[3]
			boundaryStart := parts[4]

			return header + newValue + boundaryStart
		}
		return match // parsing failed, return original
	})
}
