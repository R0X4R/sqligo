package tamper

import (
	"strings"
)

// Tamper defines the interface for all tamper scripts
type Tamper interface {
	Name() string
	Description() string
	Apply(payload string) string
}

// Registry holds all available tamper scripts
var Registry = make(map[string]Tamper)

// Register adds a tamper script to the registry
func Register(t Tamper) {
	Registry[strings.ToLower(t.Name())] = t
}

// Get retrieves a tamper script by name
func Get(name string) (Tamper, bool) {
	t, ok := Registry[strings.ToLower(name)]
	return t, ok
}

// ApplyChain applies multiple tamper scripts in sequence
func ApplyChain(payload string, tamperNames []string) string {
	result := payload
	for _, name := range tamperNames {
		name = strings.TrimSpace(name)
		if t, ok := Get(name); ok {
			result = t.Apply(result)
		}
	}
	return result
}

// ListAll returns all registered tamper script names
func ListAll() []string {
	names := make([]string, 0, len(Registry))
	for name := range Registry {
		names = append(names, name)
	}
	return names
}
