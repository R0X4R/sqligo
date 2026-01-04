package utils

import (
	"fmt"
	"math"
	"net/url"
	"strings"

	"github.com/R0X4R/sqligo/pkg/config"
)

func ToString(v interface{}) string {
	return fmt.Sprintf("%v", v)
}

// GetRatio calculates the similarity ratio between two strings
// Logic aims to behave similarly to Python's difflib.SequenceMatcher.ratio()
// using Levenshtein distance for approximation of similarity.
func GetRatio(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	dist := levenshtein(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))

	// Similarity = 1 - (distance / max_length)
	return 1.0 - (float64(dist) / maxLen)
}

// levenshtein calculates the Levenshtein distance between two strings
func levenshtein(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	rows := len(r1) + 1
	cols := len(r2) + 1
	dist := make([][]int, rows)

	for i := 0; i < rows; i++ {
		dist[i] = make([]int, cols)
		dist[i][0] = i
	}
	for j := 0; j < cols; j++ {
		dist[0][j] = j
	}

	for i := 1; i < rows; i++ {
		for j := 1; j < cols; j++ {
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			dist[i][j] = min(
				dist[i-1][j]+1,      // deletion
				dist[i][j-1]+1,      // insertion
				dist[i-1][j-1]+cost, // substitution
			)
		}
	}
	return dist[rows-1][cols-1]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// UrlEncode encodes a string into URL format
func UrlEncode(s string) string {
	if config.GlobalConfig.SkipUrlEncoding {
		return s
	}
	return url.QueryEscape(s)
}

// UrlDecode decodes a URL encoded string
func UrlDecode(s string) (string, error) {
	return url.QueryUnescape(s)
}

// ToList converts a single string to a list if it's not already (stub)
// In Go, we usually handle slices explicitly, but this mirrors Python's to_list
func ToList(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}

// ReplaceWith replaces a character in a string with another string
func ReplaceWith(s string, char string, replacement string) string {
	return strings.ReplaceAll(s, char, replacement)
}

// DbmsFullName returns the full name of the DBMS (Stub logic)
func DbmsFullName(alias string) string {
	alias = strings.ToLower(alias)
	switch alias {
	case "mysql":
		return "MySQL"
	case "pgsql", "postgres", "postgresql":
		return "PostgreSQL"
	case "mssql":
		return "Microsoft SQL Server"
	case "oracle":
		return "Oracle"
	default:
		return alias
	}
}
