package request

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

// ParseRequestFile reads a raw HTTP request file and returns URL, Data, Headers, Method
func ParseRequestFile(filePath string, useSsl bool) (string, string, map[string]string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", nil, "", err
	}
	defer file.Close()

	// Use http.ReadRequest to parse standard HTTP
	req, err := http.ReadRequest(bufio.NewReader(file))
	if err != nil {
		return "", "", nil, "", fmt.Errorf("failed to parse request file: %v", err)
	}

	// Extract Host
	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}
	if host == "" {
		return "", "", nil, "", fmt.Errorf("no Host header found in request file")
	}

	// Construct URL
	scheme := "http"
	if useSsl {
		scheme = "https"
	}
	urlStr := fmt.Sprintf("%s://%s%s", scheme, host, req.URL.RequestURI())

	// Extract Headers
	headers := make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[k] = v[0] // Simple handling, take first
		}
	}

	// Extract Body
	var body string
	if req.Body != nil {
		bodyBytes, err := ioutil.ReadAll(req.Body)
		if err == nil {
			body = string(bodyBytes)
		}
	}

	return urlStr, body, headers, req.Method, nil
}
