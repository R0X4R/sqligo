package request

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/R0X4R/sqligo/pkg/config"
	"github.com/R0X4R/sqligo/pkg/logger"
	"github.com/R0X4R/sqligo/pkg/utils"
)

type Request struct {
	Url       string
	Method    string
	Headers   map[string]string
	Data      string
	Cookies   string
	UserAgent string
	Proxy     string
	Timeout   int
}

type Response struct {
	StatusCode    int
	Body          string
	Headers       map[string]string
	ContentLength int64
	TimeTaken     float64
	Ok            bool
}

// NewRequest creates a new Request object
func NewRequest(urlStr string) *Request {
	req := &Request{
		Url:     urlStr,
		Method:  "GET",
		Headers: make(map[string]string),
		Timeout: 30,
	}

	// Apply Global Config
	if config.GlobalConfig != nil {
		req.Proxy = config.GlobalConfig.Proxy
		req.Timeout = config.GlobalConfig.Timeout
		if req.Timeout == 0 {
			req.Timeout = 30
		}

		// User-Agent Selection Logic
		if config.GlobalConfig.RandomAgent {
			req.UserAgent = utils.GetRandomUserAgent()
		} else if config.GlobalConfig.Mobile {
			req.UserAgent = utils.GetMobileUserAgent()
		} else if config.GlobalConfig.UserAgent != "" {
			req.UserAgent = config.GlobalConfig.UserAgent
		}

		req.Cookies = config.GlobalConfig.Cookie

		if config.GlobalConfig.Referer != "" {
			req.Headers["Referer"] = config.GlobalConfig.Referer
		}

		if config.GlobalConfig.Header != "" {
			// Stub: split by comma or newline if multiple, checking standard format Header: Value
			parts := strings.SplitN(config.GlobalConfig.Header, ":", 2)
			if len(parts) == 2 {
				req.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		// Merge Headers Map (from -r file)
		if config.GlobalConfig.Headers != nil {
			for k, v := range config.GlobalConfig.Headers {
				req.Headers[k] = v
			}
		}
	}
	return req
}

// Execute performs the HTTP request
func (r *Request) Execute() (*Response, error) {
	client := &http.Client{
		Timeout: time.Duration(r.Timeout) * time.Second,
	}

	// Proxy handling
	if r.Proxy != "" {
		proxyURL, err := url.Parse(r.Proxy)
		if err == nil {
			client.Transport = &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
	} else {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	var req *http.Request
	var err error

	if r.Data != "" {
		r.Method = "POST"
		req, err = http.NewRequest(r.Method, r.Url, strings.NewReader(r.Data))
		// Auto-detect or use config for JSON
		if config.GlobalConfig != nil && config.GlobalConfig.IsJson {
			req.Header.Set("Content-Type", "application/json")
		} else {
			if req.Header.Get("Content-Type") == "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}
	} else {
		req, err = http.NewRequest(r.Method, r.Url, nil)
	}

	if err != nil {
		return nil, err
	}

	// Set Headers
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	if r.UserAgent != "" {
		req.Header.Set("User-Agent", r.UserAgent)
	}
	if r.Cookies != "" {
		req.Header.Set("Cookie", r.Cookies)
	}
	// Common headers if not present
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}

	logger.Debug("Requesting %s", r.Url)

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start).Seconds()

	if err != nil {
		logger.Debug("Request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	response := &Response{
		StatusCode:    resp.StatusCode,
		Body:          string(bodyBytes),
		Headers:       make(map[string]string),
		ContentLength: resp.ContentLength,
		TimeTaken:     duration,
		Ok:            resp.StatusCode >= 200 && resp.StatusCode < 400,
	}

	for k, v := range resp.Header {
		response.Headers[k] = strings.Join(v, ";")
	}

	return response, nil
}
