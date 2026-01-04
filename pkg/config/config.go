package config

import (
	"sync"
)

type Config struct {
	Vectors             string
	IsString            bool
	IsJson              bool
	IsXml               bool
	IsMultipart         bool
	SkipUrlEncoding     bool
	FilePaths           *FilePaths
	Proxy               string
	TextOnly            bool
	String              string
	NotString           string
	Code                int
	MatchRatio          float64
	Retry               int
	Base                string
	Attack01            string
	Backend             string
	Batch               bool
	ContinueOnHttpError bool
	FollowRedirects     bool
	Threads             int
	Timeout             int
	Delay               int
	TimeSec             int
	ConfirmPayloads     bool
	SafeChars           string
	TestFilter          string
	Prioritize          bool
	FreshQueries        bool
	IgnoreCode          string // Comma separated or "*"
	RandomAgent         bool
	Mobile              bool

	// Tamper Scripts
	Tamper []string // List of tamper script names
	Level  int      // Test level (1-3)

	// Evasion / Custom Headers
	UserAgent string
	Cookie    string
	Referer   string
	Header    string
	Headers   map[string]string // Parsed from request file

	// Audit Gap Fields
	RequestFile   string
	TestParameter string
	Prefix        string
	Suffix        string
	Silent        bool // Silent mode - only show results

	// Runtime internal states
	mtMode         bool
	multitargetCsv string
	mu             sync.Mutex
}

type FilePaths struct {
	Session  string
	Logs     string
	Filepath string
}

var GlobalConfig *Config

func Init() {
	GlobalConfig = &Config{
		Retry:   3,
		TimeSec: 5,
		Timeout: 30,
		Delay:   0,
		mu:      sync.Mutex{},
	}
}

// GetIgnoreCodes returns a slice of ignored HTTP status codes
// TODO: Implement parsing logic similar to properties in python
func (c *Config) GetIgnoreCodes() []int {
	// wrapper for parsing c.IgnoreCode string
	return []int{}
}
