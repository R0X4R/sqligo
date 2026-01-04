package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"io"
	"mime"
	"mime/multipart"

	"github.com/R0X4R/sqligo/pkg/config"
	"github.com/R0X4R/sqligo/pkg/core"
	"github.com/R0X4R/sqligo/pkg/extractor"
	"github.com/R0X4R/sqligo/pkg/logger"
	"github.com/R0X4R/sqligo/pkg/request"
	_ "github.com/R0X4R/sqligo/pkg/tamper/scripts" // Import to register tamper scripts

	"github.com/projectdiscovery/goflags"
)

func main() {
	config.Init()

	var urlStr string
	var data string
	var requestFile string
	var multipleFile string
	var help bool
	var version bool
	var dbs, tables, columns, dump bool
	var banner, currentUser, currentDb, isDba bool
	var db, table, column string
	var testParameter string
	var sqlShell bool

	// Evasion / Request Flags
	var proxy, userAgent, cookie, referer, header string
	var delay, timeout, retries int
	var randomAgent, mobile, skipUrlEncode bool
	var level int
	var tamper string
	var prefix, suffix, stringMatch, notStringMatch string
	var codeMatch int
	var silent bool

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("sqligo - Advanced SQL injection detection and exploitation tool")

	// Target group
	flagSet.CreateGroup("target", "Target",
		flagSet.StringVarP(&urlStr, "url", "u", "", "target URL (e.g., http://example.com/page.php?id=1)"),
		flagSet.StringVarP(&data, "data", "d", "", "data string to be sent through POST (e.g., \"id=1\")"),
		flagSet.StringVarP(&requestFile, "request-file", "r", "", "load HTTP request from a file"),
		flagSet.StringVarP(&multipleFile, "multiple", "m", "", "scan multiple URLs from file (one per line)"),
		flagSet.StringVarP(&testParameter, "parameter", "p", "", "testable parameter(s)"),
	)

	// Enumeration group
	flagSet.CreateGroup("enumeration", "Enumeration",
		flagSet.BoolVar(&dbs, "dbs", false, "enumerate DBMS databases"),
		flagSet.BoolVar(&tables, "tables", false, "enumerate DBMS database tables"),
		flagSet.BoolVar(&columns, "columns", false, "enumerate DBMS database table columns"),
		flagSet.BoolVar(&dump, "dump", false, "dump DBMS database table entries"),
		flagSet.StringVar(&db, "D", "", "DBMS database to enumerate"),
		flagSet.StringVar(&table, "T", "", "DBMS database table(s) to enumerate"),
		flagSet.StringVar(&column, "C", "", "DBMS database table column(s) to enumerate"),
	)

	// Detection group
	flagSet.CreateGroup("detection", "Detection",
		flagSet.BoolVarP(&banner, "banner", "b", false, "retrieve DBMS banner"),
		flagSet.BoolVar(&currentUser, "current-user", false, "retrieve DBMS current user"),
		flagSet.BoolVar(&currentDb, "current-db", false, "retrieve DBMS current database"),
		flagSet.BoolVar(&isDba, "is-dba", false, "detect if the DBMS current user is DBA"),
		flagSet.BoolVar(&sqlShell, "sql-shell", false, "prompt for an interactive SQL shell"),
	)

	// Request group
	flagSet.CreateGroup("request", "Request",
		flagSet.StringVar(&proxy, "proxy", "", "use a proxy to connect to the target URL"),
		flagSet.StringVarP(&userAgent, "user-agent", "A", "", "HTTP User-Agent header value"),
		flagSet.StringVar(&cookie, "cookie", "", "HTTP Cookie header value"),
		flagSet.StringVar(&referer, "referer", "", "HTTP Referer header value"),
		flagSet.StringVarP(&header, "header", "H", "", "extra header (e.g. \"X-Forwarded-For: 127.0.0.1\")"),
		flagSet.IntVar(&delay, "delay", 0, "delay in seconds between each HTTP request"),
		flagSet.IntVar(&timeout, "timeout", 30, "seconds to wait before timeout connection"),
		flagSet.IntVar(&retries, "retries", 3, "retries when the connection related error occurs"),
	)

	// Injection group
	flagSet.CreateGroup("injection", "Injection",
		flagSet.IntVar(&level, "level", 1, "level of tests to perform (1-3, default 1)"),
		flagSet.StringVar(&prefix, "prefix", "", "injection payload prefix string"),
		flagSet.StringVar(&suffix, "suffix", "", "injection payload suffix string"),
	)

	// Detection Tuning group
	flagSet.CreateGroup("detection-tuning", "Detection Tuning",
		flagSet.StringVar(&stringMatch, "string", "", "string to match when query is evaluated to True"),
		flagSet.StringVar(&notStringMatch, "not-string", "", "string to match when query is evaluated to False"),
		flagSet.IntVar(&codeMatch, "code", 0, "HTTP code to match when query is evaluated to True"),
	)

	// Evasion group
	flagSet.CreateGroup("evasion", "Evasion",
		flagSet.StringVar(&tamper, "tamper", "", "use tamper script(s) (comma-separated, e.g., 'space2comment,randomcase')"),
		flagSet.BoolVar(&randomAgent, "random-agent", false, "use randomly selected HTTP User-Agent header value"),
		flagSet.BoolVar(&mobile, "mobile", false, "imitate smartphone through HTTP User-Agent header"),
		flagSet.BoolVar(&skipUrlEncode, "skip-urlencode", false, "skip URL encoding of payload data"),
	)

	// General group
	flagSet.CreateGroup("general", "General",
		flagSet.BoolVarP(&help, "help", "h", false, "display this help message and exit"),
		flagSet.BoolVar(&version, "version", false, "show program's version number and exit"),
		flagSet.BoolVarP(&silent, "silent", "q", false, "silent mode - only show results"),
	)

	if err := flagSet.Parse(); err != nil {
		logger.Critical("Error parsing flags: %v", err)
		os.Exit(1)
	}

	// Handle help flag first
	if help {
		fmt.Println("sqligo - Advanced SQL injection detection and exploitation tool")
		fmt.Println("\nUsage: sqligo [options]")
		fmt.Println("\nTARGET:")
		fmt.Println("  -u, --url string              target URL (e.g., http://example.com/page.php?id=1)")
		fmt.Println("  -d, --data string             data string to be sent through POST")
		fmt.Println("  -r, --request-file string     load HTTP request from a file")
		fmt.Println("  -m, --multiple string         scan multiple URLs from file (one per line)")
		fmt.Println("  -p, --parameter string        testable parameter(s)")
		fmt.Println("\nENUMERATION:")
		fmt.Println("  --dbs                         enumerate DBMS databases")
		fmt.Println("  --tables                      enumerate DBMS database tables")
		fmt.Println("  --columns                     enumerate DBMS database table columns")
		fmt.Println("  --dump                        dump DBMS database table entries")
		fmt.Println("  -D string                     DBMS database to enumerate")
		fmt.Println("  -T string                     DBMS database table(s) to enumerate")
		fmt.Println("  -C string                     DBMS database table column(s) to enumerate")
		fmt.Println("\nDETECTION:")
		fmt.Println("  -b, --banner                  retrieve DBMS banner")
		fmt.Println("  --current-user                retrieve DBMS current user")
		fmt.Println("  --current-db                  retrieve DBMS current database")
		fmt.Println("  --is-dba                      detect if the DBMS current user is DBA")
		fmt.Println("  --sql-shell                   prompt for an interactive SQL shell")
		fmt.Println("\nREQUEST:")
		fmt.Println("  --proxy string                use a proxy to connect to the target URL")
		fmt.Println("  -A, --user-agent string       HTTP User-Agent header value")
		fmt.Println("  --cookie string               HTTP Cookie header value")
		fmt.Println("  --referer string              HTTP Referer header value")
		fmt.Println("  -H, --header string           extra header (e.g. \"X-Forwarded-For: 127.0.0.1\")")
		fmt.Println("  --delay int                   delay in seconds between each HTTP request")
		fmt.Println("  --timeout int                 seconds to wait before timeout connection (default 30)")
		fmt.Println("  --retries int                 retries when the connection related error occurs (default 3)")
		fmt.Println("\nINJECTION:")
		fmt.Println("  --level int                   level of tests to perform (1-3, default 1)")
		fmt.Println("  --prefix string               injection payload prefix string")
		fmt.Println("  --suffix string               injection payload suffix string")
		fmt.Println("\nDETECTION TUNING:")
		fmt.Println("  --string string               string to match when query is evaluated to True")
		fmt.Println("  --not-string string           string to match when query is evaluated to False")
		fmt.Println("  --code int                    HTTP code to match when query is evaluated to True")
		fmt.Println("\nEVASION:")
		fmt.Println("  --tamper string               use tamper script(s) (comma-separated, e.g., 'space2comment,randomcase')")
		fmt.Println("  --random-agent                use randomly selected HTTP User-Agent header value")
		fmt.Println("  --mobile                      imitate smartphone through HTTP User-Agent header")
		fmt.Println("  --skip-urlencode              skip URL encoding of payload data")
		fmt.Println("\nGENERAL:")
		fmt.Println("  -h, --help                    display this help message and exit")
		fmt.Println("  --version                     show program's version number and exit")
		fmt.Println("  -q, --silent                  silent mode - only show results")
		fmt.Println("\nNOTE:")
		fmt.Println("  Multiple target scans (-m) automatically save progress to <file>.progress")
		fmt.Println("  If interrupted, simply re-run the same command to resume from where it left off")
		fmt.Println("\nExamples:")
		fmt.Println("  sqligo -u \"http://example.com/page.php?id=1\"")
		fmt.Println("  sqligo -u \"http://example.com/page.php?id=1\" --dbs")
		fmt.Println("  sqligo -m targets.txt --banner -q")
		fmt.Println("  sqligo -m targets.txt --banner -q")
		fmt.Println("  sqligo -u \"http://example.com/page.php?id=1\" --tamper \"space2comment,randomcase\" --banner")
		os.Exit(0)
	}

	if version {
		fmt.Println("github.com/R0X4R/sqligo v1.0")
		os.Exit(0)
	}

	if urlStr == "" && requestFile == "" && multipleFile == "" {
		logger.Critical("Target URL is required. Use -u, -r, or -m. See --help for more info.")
		os.Exit(1)
	}

	// Update Config
	config.GlobalConfig.Proxy = proxy
	config.GlobalConfig.UserAgent = userAgent
	config.GlobalConfig.Cookie = cookie
	config.GlobalConfig.Referer = referer
	config.GlobalConfig.Delay = delay
	config.GlobalConfig.Timeout = timeout
	config.GlobalConfig.Retry = retries
	config.GlobalConfig.RandomAgent = randomAgent
	config.GlobalConfig.Mobile = mobile
	config.GlobalConfig.SkipUrlEncoding = skipUrlEncode
	config.GlobalConfig.Level = level
	config.GlobalConfig.RequestFile = requestFile
	config.GlobalConfig.TestParameter = testParameter
	config.GlobalConfig.Prefix = prefix
	config.GlobalConfig.Suffix = suffix
	config.GlobalConfig.String = stringMatch
	config.GlobalConfig.NotString = notStringMatch
	config.GlobalConfig.Code = codeMatch
	config.GlobalConfig.Silent = silent

	// Parse tamper scripts
	if tamper != "" {
		config.GlobalConfig.Tamper = strings.Split(tamper, ",")
		for i := range config.GlobalConfig.Tamper {
			config.GlobalConfig.Tamper[i] = strings.TrimSpace(config.GlobalConfig.Tamper[i])
		}
	}

	if header != "" {
		config.GlobalConfig.Header = header
	}

	// Handle Request File (-r)
	if requestFile != "" {
		logger.Info("Parsing request file: %s", requestFile)
		pUrl, pData, pHeaders, _, err := request.ParseRequestFile(requestFile, false)
		if err != nil {
			logger.Critical("Failed to parse request file: %v", err)
			os.Exit(1)
		}
		urlStr = pUrl
		data = pData
		config.GlobalConfig.Headers = pHeaders
		logger.Info("Target from file: %s", urlStr)
		if len(pHeaders) > 0 {
			logger.Info("Loaded %d headers from file", len(pHeaders))
		}
	}

	// Handle Multiple Targets (-m)
	var targetUrls []string
	if multipleFile != "" {
		file, err := os.Open(multipleFile)
		if err != nil {
			logger.Critical("Failed to open multiple targets file: %v", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targetUrls = append(targetUrls, line)
			}
		}

		if err := scanner.Err(); err != nil {
			logger.Critical("Error reading multiple targets file: %v", err)
			os.Exit(1)
		}

		if len(targetUrls) == 0 {
			logger.Critical("No valid URLs found in file: %s", multipleFile)
			os.Exit(1)
		}

		logger.Info("Loaded %d target URLs from file", len(targetUrls))

		// Resume functionality - check for progress file
		resumeFile := multipleFile + ".progress"
		scannedUrls := make(map[string]bool)

		// Load previously scanned URLs
		if resumeData, err := os.ReadFile(resumeFile); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(resumeData)))
			for scanner.Scan() {
				scannedUrls[strings.TrimSpace(scanner.Text())] = true
			}
			if len(scannedUrls) > 0 {
				logger.Info("Resuming scan - %d URLs already scanned", len(scannedUrls))
			}
		}
	} else {
		// Single target
		targetUrls = []string{urlStr}
	}

	// Scan each target
	var resumeFile string
	if multipleFile != "" {
		resumeFile = multipleFile + ".progress"
	}

	for targetIdx, targetUrl := range targetUrls {
		// Skip if already scanned (resume functionality)
		if multipleFile != "" {
			// Check if already scanned
			if resumeData, err := os.ReadFile(resumeFile); err == nil {
				if strings.Contains(string(resumeData), targetUrl) {
					logger.Info("Skipping already scanned target %d/%d: %s", targetIdx+1, len(targetUrls), targetUrl)
					continue
				}
			}
		}

		if len(targetUrls) > 1 {
			logger.Info("=== Scanning target %d/%d: %s ===", targetIdx+1, len(targetUrls), targetUrl)
		}

		// Use targetUrl instead of urlStr for this iteration
		scanTarget(targetUrl, data, testParameter, level, dbs, tables, columns, dump, banner, currentUser, currentDb, isDba, sqlShell, db, table, column)

		// Mark as scanned (resume functionality)
		if multipleFile != "" {
			f, err := os.OpenFile(resumeFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				f.WriteString(targetUrl + "\n")
				f.Close()
			}
		}
	}

	// Clean up progress file on successful completion
	if multipleFile != "" && resumeFile != "" {
		os.Remove(resumeFile)
		logger.Info("Scan completed successfully - progress file removed")
	}

	logger.Info("All scans finished.")
}

// scanTarget performs the actual scanning logic for a single target
func scanTarget(urlStr, data, testParameter string, level int, dbs, tables, columns, dump, banner, currentUser, currentDb, isDba, sqlShell bool, db, table, column string) {
	logger.Info("Starting SQLiGO...")
	logger.Info("Target: %s", urlStr)

	// Basic connectivity check (this already logs "Testing connection" and "Target is up")
	basicRes := core.BasicCheck(urlStr, data)
	if basicRes == nil {
		logger.Critical("Target appears to be down or unreachable")
		return // Don't exit, just return to continue with next target
	}

	// Scan
	logger.Info("Scanning...")

	// Stub: Parse parameters from URL and Data
	// Use a map to track params and their source (URL vs Body)?
	// For MVP parity, just iterate all finding params.

	type TargetParam struct {
		Name        string
		Value       string
		InUrl       bool
		InHeader    bool
		InJson      bool
		InMultipart bool // New field
		InXml       bool
	}
	var targets []TargetParam

	if strings.Contains(urlStr, "?") {
		parts := strings.Split(urlStr, "?")
		if len(parts) > 1 {
			query := parts[1]
			params := strings.Split(query, "&")
			for _, p := range params {
				kv := strings.Split(p, "=")
				if len(kv) >= 2 {
					targets = append(targets, TargetParam{Name: kv[0], Value: kv[1], InUrl: true})
				}
			}
		}
	}

	if data != "" {
		// Try parsing as JSON first
		var jsonData map[string]interface{}
		if json.Unmarshal([]byte(data), &jsonData) == nil {
			// It IS JSON
			config.GlobalConfig.IsJson = true
			for k, v := range jsonData {
				strVal := fmt.Sprintf("%v", v)
				targets = append(targets, TargetParam{Name: k, Value: strVal, InUrl: false, InJson: true})
			}
		} else {
			// Check for Multipart
			// Heuristic: Check if Content-Type header has boundary (if from -r) OR if data contains boundaries
			isMultipart := false
			var boundary string

			// Check header first (if existing)
			if config.GlobalConfig.Header != "" { // Check manually set header
				// Simplified check
				if strings.Contains(strings.ToLower(config.GlobalConfig.Header), "multipart/form-data") {
					_, params, err := mime.ParseMediaType(config.GlobalConfig.Header)
					if err == nil {
						boundary = params["boundary"]
						isMultipart = true
					}
				}
			}
			// Check parsed headers from file
			if !isMultipart && config.GlobalConfig.Headers != nil {
				for k, v := range config.GlobalConfig.Headers {
					if strings.EqualFold(k, "Content-Type") && strings.Contains(strings.ToLower(v), "multipart/form-data") {
						_, params, err := mime.ParseMediaType(v)
						if err == nil {
							boundary = params["boundary"]
							isMultipart = true
						}
					}
				}
			}

			if !isMultipart && strings.Contains(data, "--") {
				lines := strings.Split(data, "\n")
				if len(lines) > 0 {
					possibleBoundary := strings.TrimSpace(lines[0])
					if strings.HasPrefix(possibleBoundary, "--") {
						boundary = possibleBoundary[2:]
						// actually multipart reader needs just the boundary string
						isMultipart = true
					}
				}
			}

			if isMultipart && boundary != "" {
				config.GlobalConfig.IsMultipart = true
				// Parse Multipart
				// We need to construct a reader
				bodyReader := strings.NewReader(data)
				mr := multipart.NewReader(bodyReader, boundary)
				for {
					p, err := mr.NextPart()
					if err == io.EOF {
						break
					}
					if err != nil {
						break
					}
					name := p.FormName()
					if name != "" {
						slurp, _ := io.ReadAll(p)
						targets = append(targets, TargetParam{Name: name, Value: string(slurp), InUrl: false, InMultipart: true})
					}
				}
			} else {
				// Check for XML
				trimmed := strings.TrimSpace(data)
				if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") {
					config.GlobalConfig.IsXml = true
					decoder := xml.NewDecoder(strings.NewReader(trimmed))
					var elementStack []string
					for {
						t, err := decoder.Token()
						if err != nil {
							break
						}
						switch se := t.(type) {
						case xml.StartElement:
							elementStack = append(elementStack, se.Name.Local)
						case xml.EndElement:
							if len(elementStack) > 0 {
								elementStack = elementStack[:len(elementStack)-1]
							}
						case xml.CharData:
							content := string(se)
							if strings.TrimSpace(content) != "" && len(elementStack) > 0 {
								tagName := elementStack[len(elementStack)-1]
								targets = append(targets, TargetParam{Name: tagName, Value: content, InUrl: false, InXml: true})
							}
						}
					}
				} else {
					// Standard Form Data
					params := strings.Split(data, "&")
					for _, p := range params {
						kv := strings.Split(p, "=")
						if len(kv) >= 2 {
							targets = append(targets, TargetParam{Name: kv[0], Value: kv[1], InUrl: false})
						}
					}
				}
			}
		}
	}

	// Level 2: Cookie Injection
	if level >= 2 && config.GlobalConfig.Cookie != "" {
		// Parse cookie string: "key=value; key2=value2"
		parts := strings.Split(config.GlobalConfig.Cookie, ";")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			kv := strings.Split(p, "=")
			if len(kv) >= 2 {
				targets = append(targets, TargetParam{Name: kv[0], Value: kv[1], InUrl: false, InHeader: true})
			}
		}
	}

	// Level 3: Header Injection
	if level >= 3 {
		// Inject User-Agent
		if config.GlobalConfig.UserAgent != "" {
			targets = append(targets, TargetParam{Name: "User-Agent", Value: config.GlobalConfig.UserAgent, InUrl: false, InHeader: true})
		}
		// Inject Referer
		if config.GlobalConfig.Referer != "" {
			targets = append(targets, TargetParam{Name: "Referer", Value: config.GlobalConfig.Referer, InUrl: false, InHeader: true})
		}
		// Custom Header?
		if config.GlobalConfig.Header != "" {
			// header flag usually "Name: Value"
			kv := strings.SplitN(config.GlobalConfig.Header, ":", 2)
			if len(kv) == 2 {
				targets = append(targets, TargetParam{Name: strings.TrimSpace(kv[0]), Value: strings.TrimSpace(kv[1]), InUrl: false, InHeader: true})
			}
		}
	}

	for _, t := range targets {
		// Filter by -p (testParameter)
		if testParameter != "" {
			match := false
			params := strings.Split(testParameter, ",")
			for _, p := range params {
				if strings.TrimSpace(p) == t.Name {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		key := t.Name
		val := t.Value
		// logger.Info("Testing parameter '%s'...", key)

		// Perform Checks - Ordered from FASTEST to SLOWEST
		// 1. Error-based (fastest - instant if errors shown)
		res := core.CheckErrorBasedSqli(urlStr, data, key, val, t.InHeader, t.InJson, t.InMultipart, t.InXml)
		if !res.Vulnerable {
			// 2. Boolean-based (fast - simple true/false)
			res = core.CheckBooleanBasedSqli(urlStr, data, key, val, t.InHeader, t.InJson, t.InMultipart, t.InXml)
		}
		if !res.Vulnerable {
			// 3. Union-based (medium - needs column detection)
			res = core.CheckUnionBasedSqli(urlStr, data, key, val, t.InHeader, t.InJson, t.InMultipart, t.InXml)
		}
		if !res.Vulnerable {
			// 4. Time-based (slowest - waits for delays)
			res = core.CheckTimeBasedSqli(urlStr, data, key, val, t.InHeader, t.InJson, t.InMultipart, t.InXml)
		}
		if res.Vulnerable {
			logger.Success("Parameter '%s' is vulnerable!", key)
			logger.Success("Type: %s", res.InjectionType)
			logger.Success("Vector: %s", res.Vector)

			// Only show Union-specific info for Union-based injections
			if res.InjectionType == "Union-based" {
				logger.Success("Column Count: %d", res.ColumnCount)
				logger.Success("Injectable Columns: %v", res.InjectableColumns)
			}

			// Exploitation / Enumeration
			ext := extractor.NewExtractor(urlStr, data, res.Vector, key, res.Backend)

			// Set Union-specific fields only if Union-based
			if res.InjectionType == "Union-based" {
				ext.InjectableColumns = res.InjectableColumns
				ext.ColumnCount = res.ColumnCount
			}

			if dbs {
				dbsList := ext.ExtractDbs()
				for _, d := range dbsList {
					logger.Success("Database: %s", d)
				}
			}

			if tables {
				if db == "" {
					db = ext.ExtractCurrentDB()
				}
				logger.Info("Fetching tables for DB: %s", db)
				tbls := ext.ExtractTables(db)
				for _, t := range tbls {
					logger.Success("Table: %s", t)
				}
			}

			if columns {
				if db == "" {
					db = ext.ExtractCurrentDB()
				}
				if table == "" {
					logger.Error("Table name is required for column extraction. Use -T")
				} else {
					cols := ext.ExtractColumns(db, table)
					for _, c := range cols {
						logger.Success("Column: %s", c)
					}
				}
			}

			if dump {
				if db == "" {
					db = ext.ExtractCurrentDB()
				}
				if table == "" {
					logger.Error("Table name is required for dump. Use -T")
				} else {
					// Need columns to dump
					cols := ext.ExtractColumns(db, table)
					ext.DumpTable(db, table, cols)
				}
			}

			if !dbs && !tables && !columns && !dump && !banner && !currentUser && !currentDb && !isDba {
				bannerStr := ext.ExtractBanner()
				logger.Success("Banner: %s", bannerStr)
			}

			if banner {
				logger.Success("Banner: %s", ext.ExtractBanner())
			}
			if currentUser {
				logger.Success("Current User: %s", ext.ExtractCurrentUser())
			}
			if currentDb {
				logger.Success("Current DB: %s", ext.ExtractCurrentDB())
			}
			if isDba {
				dba := ext.ExtractIsDba()
				logger.Success("Is DBA: %v", dba)
			}

			if sqlShell {
				logger.Info("Entering SQL Shell. Type 'exit' or 'quit' to leave.")
				scanner := bufio.NewScanner(os.Stdin)
				for {
					fmt.Print("sql-shell> ")
					if !scanner.Scan() {
						break
					}
					query := strings.TrimSpace(scanner.Text())
					if query == "" {
						continue
					}
					if strings.EqualFold(query, "exit") || strings.EqualFold(query, "quit") {
						break
					}

					data := ext.ExtractData(query)
					logger.Success("\n%s\n", data)
				}
			}

			break
		}
	}

	logger.Info("Finishing scan.")
}
