package logger

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/R0X4R/sqligo/pkg/config"

	"github.com/fatih/color"
)

// Level defines the logging level
type Level int

const (
	INFO Level = iota
	SUCCESS
	WARNING
	ERROR
	CRITICAL
	DEBUG
	PAYLOAD
	TRAFFIC_OUT
	TRAFFIC_IN
)

var (
	mutex        sync.Mutex
	currentLevel Level = INFO

	// Colors
	colorInfo     = color.New(color.FgCyan)
	colorSuccess  = color.New(color.FgGreen, color.Bold)
	colorWarning  = color.New(color.FgYellow)
	colorError    = color.New(color.FgRed, color.Bold)
	colorCritical = color.New(color.BgRed, color.FgWhite, color.Bold)
	colorDebug    = color.New(color.FgMagenta)
	colorPayload  = color.New(color.FgHiBlue)
	colorTraffic  = color.New(color.FgHiBlack) // Gray-ish
)

// SetLevel sets the global logging level
func SetLevel(l Level) {
	mutex.Lock()
	defer mutex.Unlock()
	currentLevel = l
}

func log(level Level, prefix, message string, c *color.Color) {
	// Silent mode: only show SUCCESS, ERROR, CRITICAL
	if config.GlobalConfig != nil && config.GlobalConfig.Silent {
		if level != SUCCESS && level != ERROR && level != CRITICAL {
			return
		}
	}

	show := false

	// Always show critical/error/warning/success/info unless very restrictive (not implemented here)
	if level == INFO || level == SUCCESS || level == WARNING || level == ERROR || level == CRITICAL {
		show = true
	} else if currentLevel >= DEBUG && level == DEBUG {
		show = true
	} else if currentLevel >= PAYLOAD && level == PAYLOAD {
		show = true
	} else if currentLevel >= TRAFFIC_OUT && level == TRAFFIC_OUT {
		show = true
	} else if currentLevel >= TRAFFIC_IN && level == TRAFFIC_IN {
		show = true
	}

	if !show {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	formattedPrefix := fmt.Sprintf("[%s] [%s]", timestamp, prefix)

	mutex.Lock()
	defer mutex.Unlock()

	if c != nil {
		c.Printf("%s ", formattedPrefix)
	} else {
		fmt.Printf("%s ", formattedPrefix)
	}
	fmt.Println(message)
}

func Info(format string, args ...interface{}) {
	log(INFO, "INFO", fmt.Sprintf(format, args...), colorInfo)
}

func Success(format string, args ...interface{}) {
	log(SUCCESS, "SUCCESS", fmt.Sprintf(format, args...), colorSuccess)
}

func Warning(format string, args ...interface{}) {
	log(WARNING, "WARNING", fmt.Sprintf(format, args...), colorWarning)
}

func Error(format string, args ...interface{}) {
	log(ERROR, "ERROR", fmt.Sprintf(format, args...), colorError)
}

func Critical(format string, args ...interface{}) {
	log(CRITICAL, "CRITICAL", fmt.Sprintf(format, args...), colorCritical)
}

func Debug(format string, args ...interface{}) {
	log(DEBUG, "DEBUG", fmt.Sprintf(format, args...), colorDebug)
}

func Payload(format string, args ...interface{}) {
	log(PAYLOAD, "PAYLOAD", fmt.Sprintf(format, args...), colorPayload)
}

func TrafficIn(format string, args ...interface{}) {
	log(TRAFFIC_IN, "TRAFFIC IN", fmt.Sprintf(format, args...), colorTraffic)
}

func TrafficOut(format string, args ...interface{}) {
	log(TRAFFIC_OUT, "TRAFFIC OUT", fmt.Sprintf(format, args...), colorTraffic)
}

func ReadInput(message string, batch bool, defaultInput string) string {
	fmt.Print(message)
	if batch {
		fmt.Println(defaultInput)
		return strings.ToLower(defaultInput)
	}
	var input string
	fmt.Scanln(&input)
	if input == "" {
		return strings.ToLower(defaultInput)
	}
	return strings.ToLower(input)
}

func Result(format string, args ...interface{}) {
	// Results are usually just printed plainly or with a specific color
	fmt.Printf(format+"\n", args...)
}

func Progress(format string, args ...interface{}) {
	log(INFO, "RETRIEVED", fmt.Sprintf(format, args...), colorInfo)
}
