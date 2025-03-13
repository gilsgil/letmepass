# LetMePass

A fast and versatile tool for testing web application authorization bypass techniques.

LetMePass is designed to help security researchers and penetration testers efficiently discover authorization bypass vulnerabilities by testing various path manipulation, encoding, and case modification techniques against protected endpoints.

## Features

- Multiple bypass techniques:
  - **DDS**: Directory traversal and path manipulation payloads (../, ./, etc.)
  - **ENC**: URL encoding and character encoding variations
  - **QUICK**: Common suffix modification techniques
  - **CASE**: Case permutation for path segments
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
- `-t string`: Bypass technique: dds, enc, quick, case (if not set, uses all)
- `-H string`: Custom header(s) in 'Name: Value' format (can be specified multiple times)
- `-c int`: Number of concurrent requests (default: 10)
- `-timeout int`: Timeout in seconds (default: 10)
- `-o string`: Output file (optional)
- `-v`: Verbose mode: print results as they are found (real time)
- `-all`: Test all URLs even if the initial check is not 401 or 403

### Examples

Test a single URL with all techniques:
```bash
letmepass -u https://example.com/admin
```

Test multiple URLs from a file using a specific technique:
```bash
cat urls.txt | letmepass -t dds
```

Use custom headers and output to a file:
```bash
letmepass -u https://example.com/admin -H "Authorization: Bearer token" -H "X-Custom: Value" -o results.txt
```

Run with real-time output:
```bash
letmepass -u https://example.com/admin -v
```

## Understanding Results

The output format is:
```
URL - STATUS_CODE - RESPONSE_LENGTH
```

Color coding:
- **Green**: 2xx status codes (Success)
- **Blue**: 3xx status codes (Redirection)
- **Orange**: 401 status code (Unauthorized)
- **Red**: 403 status code (Forbidden)
- **Purple**: 404 status code (Not Found)
- **Yellow**: Other 4xx status codes
- **Brown**: 5xx status codes (Server Errors)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)
