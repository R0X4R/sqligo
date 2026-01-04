package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	http.HandleFunc("/error-based", handleErrorBased)
	http.HandleFunc("/boolean-based", handleBooleanBased)
	http.HandleFunc("/time-based", handleTimeBased)

	fmt.Println("Mock SQLi Server running on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func handleErrorBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// Simulate MySQL Error if quote is present
	if strings.Contains(id, "'") {
		fmt.Fprintf(w, "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
		return
	}
	fmt.Fprintf(w, "ID is: %s", id)
}

func handleBooleanBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// Simulate Boolean Blind
	// "Hard" scenario: No error, just different content

	// Our payload usually looks like: 1 AND 1=1 -- -
	// Simple simulation:
	if strings.Contains(id, "AND 1=1") { // True Condition
		fmt.Fprintf(w, "User: Admin") // Same as normal
	} else if strings.Contains(id, "AND 1=2") { // False Condition
		fmt.Fprintf(w, "User: Guest") // Different content
	} else {
		fmt.Fprintf(w, "User: Admin") // Base content
	}
}

func handleTimeBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// Simulate Time Blind
	// Look for SLEEP(5)
	if strings.Contains(id, "SLEEP(5)") {
		time.Sleep(5 * time.Second)
	}
	fmt.Fprintf(w, "Result for ID: %s", id)
}
