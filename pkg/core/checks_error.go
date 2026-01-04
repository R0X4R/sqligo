package core

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/R0X4R/sqligo/pkg/config"
	"github.com/R0X4R/sqligo/pkg/logger"
	"github.com/R0X4R/sqligo/pkg/payloads"
	"github.com/R0X4R/sqligo/pkg/request"
	"github.com/R0X4R/sqligo/pkg/tamper"
	"github.com/R0X4R/sqligo/pkg/utils"
)

// CheckErrorBasedSqli performs error-based SQL injection checks
func CheckErrorBasedSqli(urlStr, data, param, value string, isHeader bool, isJson bool, isMultipart bool, isXml bool) *InjectionResult {
	if payloads.GlobalPayloads == nil {
		payloads.Init()
	}

	tests := payloads.GlobalPayloads.ErrorTests["error-based"]
	errorPatterns := []string{
		`SQL syntax.*MySQL`,
		`Warning.*mysql_.*`,
		`valid MySQL result`,
		`MySqlClient\.`,
		`PostgreSQL.*ERROR`,
		`Warning.*pg_.*`,
		`Driver.* SQL[\-\_\ ]*Server`,
		`OLE DB.* SQL Server`,
		`\bSQL Server[^&lt;&quot;]+Driver`,
		`Warning.*odbc_.*`,
		`\bORA-[0-9][0-9][0-9][0-9]`,
		`Oracle error`,
	}

	for _, test := range tests {
		if config.GlobalConfig.Backend != "" && test.Dbms != "" && test.Dbms != config.GlobalConfig.Backend {
			continue
		}

		// Replace [RANDNUM] or [DELIMITER] logic
		payloadStr := test.Payload
		// error payloads in Payload struct might need dynamic replacement too, doing simplified pass

		for _, comment := range test.Comments {
			// Apply Prefix/Suffix
			pref := comment.Pref
			if config.GlobalConfig.Prefix != "" {
				pref = config.GlobalConfig.Prefix + pref
			}
			suf := comment.Suf
			if config.GlobalConfig.Suffix != "" {
				suf = suf + config.GlobalConfig.Suffix
			}
			fullPayload := pref + payloadStr + suf

			// Apply tamper scripts if configured
			if len(config.GlobalConfig.Tamper) > 0 {
				fullPayload = tamper.ApplyChain(fullPayload, config.GlobalConfig.Tamper)
			}
			// Inject
			var injectedUrl string
			var injectedData string
			var injectedHeaders map[string]string

			if isHeader {
				injectedUrl = urlStr
				injectedData = data
				injectedHeaders = make(map[string]string)
				injectedHeaders[param] = value + fullPayload
			} else if isJson {
				injectedUrl = urlStr
				var jMap map[string]interface{}
				err := json.Unmarshal([]byte(data), &jMap)
				if err != nil {
					logger.Debug("Failed to unmarshal JSON data: %v", err)
					continue
				}
				jMap[param] = value + fullPayload
				byteData, err := json.Marshal(jMap)
				if err != nil {
					logger.Debug("Failed to marshal JSON data: %v", err)
					continue
				}
				injectedData = string(byteData)
			} else if isMultipart {
				injectedUrl = urlStr
				injectedData = utils.ReplaceMultipartValue(data, param, value+fullPayload)
			} else if isXml {
				injectedUrl = urlStr
				injectedData = utils.ReplaceXmlValue(data, param, value+fullPayload)
			} else {
				if data != "" {
					injectedData = strings.Replace(data, param+"="+value, param+"="+value+utils.UrlEncode(fullPayload), 1)
					injectedUrl = urlStr
				} else {
					injectedUrl = strings.Replace(urlStr, param+"="+value, param+"="+value+utils.UrlEncode(fullPayload), 1)
				}
			}

			// Perform Request
			req := request.NewRequest(injectedUrl)
			req.Data = injectedData
			if isHeader {
				for k, v := range injectedHeaders {
					req.Headers[k] = v
				}
			}
			resp, err := req.Execute()
			if err != nil {
				continue
			}

			// Check content for error patterns
			for _, pattern := range errorPatterns {
				matched, _ := regexp.MatchString(pattern, resp.Body)
				if matched {
					return &InjectionResult{
						Vulnerable:    true,
						Parameter:     param,
						InjectionType: "Error-based",
						Vector:        test.Vector,
						Payload:       fullPayload,
						Backend:       test.Dbms, // We can infer backend from error type actually
					}
				}
			}

			if config.GlobalConfig.Delay > 0 {
				time.Sleep(time.Duration(config.GlobalConfig.Delay) * time.Second)
			}
		}
	}
	return &InjectionResult{Vulnerable: false}
}
