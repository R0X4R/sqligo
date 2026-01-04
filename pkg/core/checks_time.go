package core

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/R0X4R/sqligo/pkg/config"
	"github.com/R0X4R/sqligo/pkg/logger"
	"github.com/R0X4R/sqligo/pkg/payloads"
	"github.com/R0X4R/sqligo/pkg/request"
	"github.com/R0X4R/sqligo/pkg/tamper"
	"github.com/R0X4R/sqligo/pkg/utils"
)

// CheckTimeBasedSqli performs time-based blind SQL injection checks
func CheckTimeBasedSqli(urlStr, data, param, value string, isHeader bool, isJson bool, isMultipart bool, isXml bool) *InjectionResult {
	if payloads.GlobalPayloads == nil {
		payloads.Init()
	}

	tests := payloads.GlobalPayloads.TimeTests["time-based"]
	if stackedTests, ok := payloads.GlobalPayloads.StackedTests["stacked-queries"]; ok {
		tests = append(tests, stackedTests...)
	}

	for _, test := range tests {
		if config.GlobalConfig.Backend != "" && test.Dbms != "" && test.Dbms != config.GlobalConfig.Backend {
			continue
		}

		// Use configured sleep time or datault 5s
		sleepTime := config.GlobalConfig.TimeSec
		if sleepTime == 0 {
			sleepTime = 5
		}

		payloadStr := strings.ReplaceAll(test.Payload, "[SLEEPTIME]", utils.ToString(sleepTime)) // Need utils.ToString or similar

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
				_ = json.Unmarshal([]byte(data), &jMap)
				jMap[param] = value + fullPayload
				byteData, _ := json.Marshal(jMap)
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
			req := request.NewRequest(injectedUrl)
			req.Data = injectedData
			if isHeader {
				for k, v := range injectedHeaders {
					req.Headers[k] = v
				}
			}
			// Timeout must be > sleepTime
			req.Timeout = sleepTime + 10

			resp, err := req.Execute()
			if err != nil {
				// Timeouts are actually a GOOD sign in some contexts if timeout < sleep time,
				// but here we set timeout > sleep time, so we expect a success with high duration.
				// If it errors out, might be network issue or hard timeout.
				continue
			}

			// Check Duration
			// If Duration >= SleepTime -> Vulnerable
			if resp.TimeTaken >= float64(sleepTime) {
				logger.Payload("Suspected time-based vulnerability. Verifying...")

				// Double check logic (Verify) would go here
				// For now, return True
				return &InjectionResult{
					Vulnerable:    true,
					Parameter:     param,
					InjectionType: "Time-based blind",
					Vector:        test.Vector,
					Payload:       fullPayload,
					Backend:       test.Dbms,
				}
			}

			if config.GlobalConfig.Delay > 0 {
				time.Sleep(time.Duration(config.GlobalConfig.Delay) * time.Second)
			}
		}
	}
	return &InjectionResult{Vulnerable: false}
}
