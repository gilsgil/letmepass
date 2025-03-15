# LetMePass

A fast and versatile tool for testing web application authorization bypass techniques.

LetMePass is designed to help security researchers and penetration testers efficiently discover authorization bypass vulnerabilities by testing various path manipulation, encoding, and case modification techniques against protected endpoints.

## Features

- Multiple bypass techniques:
  - **DDS**: Directory traversal and path manipulation payloads (../, ./, etc.)
  - **ENC**: URL encoding and character encoding variations
  - **QUICK**: Common suffix modification techniques
  - **CASE**: Case permutation for path segments
  - **HEADERS**: Add bypass-oriented HTTP headers
  - **REWRITE**: URL rewriting via special headers
  - **METHOD**: Test different HTTP methods
  - **ALL**: Apply all techniques at once
- Layer targeting capabilities (apply modifications to specific path segments)
- Concurrent request handling for faster testing
- Colorized output for easy result interpretation
- Customizable request headers
- Output file support
- Read URLs from stdin or specify a single target

## Installation

### Using Go Install

```bash
go install github.com/gilsgil/letmepass@latest
```

### Building from Source

```bash
git clone https://github.com/gilsgil/letmepass.git
cd letmepass
go build -o letmepass
```

## Usage

```
letmepass [options]
```

### Options

- `-u string`: Single target URL (leave blank to read from stdin)
- `-t string`: Bypass technique: dds, enc, quick, case, headers, rewrite, method, all (if not set, uses dds, enc, quick, and case)
- `-l int`: Layer to apply modifications (1-indexed). If not set, uses the last layer.
- `-full`: Apply modifications to all path layers
- `-H string`: Custom header(s) in 'Name: Value' format (can be specified multiple times)
- `-c int`: Number of concurrent requests (default: 10)
- `-timeout int`: Timeout in seconds (default: 10)
- `-o string`: Output file (optional)
- `-v`: Verbose mode: print results as they are found (real time)
- `-all`: Test all URLs even if the initial check is not 401 or 403

### Examples

Test a single URL with default techniques:
```bash
letmepass -u https://example.com/admin
```

Test multiple URLs from a file using a specific technique:
```bash
cat urls.txt | letmepass -t dds
```

Apply modifications to a specific layer (segment) of the path:
```bash
letmepass -u https://example.com/admin/panel -t case -l 1
```

Apply modifications to all layers:
```bash
letmepass -u https://example.com/admin/panel -t dds -full
```

Use custom headers and output to a file:
```bash
letmepass -u https://example.com/admin -H "Authorization: Bearer token" -H "X-Custom: Value" -o results.txt
```

Test all bypass techniques:
```bash
letmepass -u https://example.com/admin -t all
```

Run with real-time output:
```bash
letmepass -u https://example.com/admin -v
```

## Understanding Results

The output format is:
```
URL - Status: STATUS_CODE - Length: RESPONSE_LENGTH [- ExtraInfo]
```

The ExtraInfo field shows additional information like headers or HTTP methods used.

Color coding:
- **Green**: 2xx status codes (Success)
- **Blue**: 3xx status codes (Redirection)
- **Orange**: 401 status code (Unauthorized)
- **Red**: 403 status code (Forbidden)
- **Purple**: 404 status code (Not Found)
- **Yellow**: Other 4xx status codes
- **Brown**: 5xx status codes (Server Errors)

## Understanding Techniques

### DDS (Directory and Dot Traversal)
Various path traversal payloads like `../`, `./`, etc.

### ENC (Encoding)
URL encoding and character encoding variations of path segments.

### QUICK
Common path suffix modification techniques.

### CASE
Case permutation for path segments.

### HEADERS
Adds specific headers like X-Forwarded-For, X-Real-IP, etc.

### REWRITE
Tests URL rewriting via headers like X-Rewrite-URL, X-Original-URL.

### METHOD
Tests different HTTP methods (GET, POST, PUT, OPTIONS, etc.).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)
