# How to Build and Use Subfinder

## What is Subfinder?

Subfinder is a passive subdomain discovery tool that finds valid subdomains for websites by pulling data from various online sources — without sending any requests directly to the target. It is widely used for penetration testing and bug bounty hunting.

---

## Prerequisites

- **Go 1.24** or later — Download at https://go.dev/dl/
- **Git** — For cloning the project (https://github.com/projectdiscovery/subfinder)

Verify that Go is installed:

```sh
go version
```

If you see `go version go1.24.x ...`, you're good to go.

---

## How to Build

### Option 1: Build from source (recommended)

```sh
# 1. Clone the project (if you haven't already)
git clone https://github.com/projectdiscovery/subfinder.git
cd subfinder

# 2. Download dependencies
go mod tidy

# 3. Build the binary
go build -o subfinder cmd/subfinder/main.go
```

Once complete, you'll have a `subfinder` binary in the project directory, ready to use.

### Option 2: Build with Make

```sh
make build
```

### Option 3: Install via `go install` (easiest)

```sh
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

The binary will be installed to `$GOPATH/bin/subfinder`. You can run it directly if `$GOPATH/bin` is in your PATH.

### Option 4: Build with Docker

```sh
docker build -t subfinder .
```

---

## How to Use

### Show all available options

```sh
./subfinder -h
```

### Find subdomains for a single domain

```sh
./subfinder -d example.com
```

### Find subdomains for multiple domains

```sh
./subfinder -d example.com,target.com
```

### Find subdomains from a file

Create a file called `domains.txt` with one domain per line:

```
example.com
target.com
test.com
```

Then run:

```sh
./subfinder -dL domains.txt
```

### Save results to a file

```sh
./subfinder -d example.com -o results.txt
```

### Show only subdomains (no logs)

```sh
./subfinder -d example.com -silent
```

### Save results as JSON

```sh
./subfinder -d example.com -oJ -o results.json
```

### Use specific sources only

```sh
./subfinder -d example.com -s crtsh,github
```

### List all available sources

```sh
./subfinder -ls
```

### Use all sources (slower but most comprehensive)

```sh
./subfinder -d example.com -all
```

---

## Real-World Examples

### Silent enumeration with file output

```sh
./subfinder -d target.com -silent -o subdomains.txt
```

### Pipe results to another tool

```sh
./subfinder -d target.com -silent | httpx -silent
```

### Run with Docker

```sh
docker run -it subfinder -d example.com
```

---

## API Key Configuration (optional but recommended)

Many sources require API keys to work. The configuration file is located at:

- **Linux/macOS:** `~/.config/subfinder/provider-config.yaml`
- **Windows:** `%USERPROFILE%\.config\subfinder\provider-config.yaml`

Example `provider-config.yaml`:

```yaml
securitytrails:
  - YOUR_API_KEY_HERE
shodan:
  - YOUR_API_KEY_HERE
virustotal:
  - YOUR_API_KEY_HERE
github:
  - YOUR_GITHUB_TOKEN_HERE
```

You can get free API keys from each provider's website.

---

## Commonly Used Flags

| Flag       | Description                                |
|------------|--------------------------------------------|
| `-d`       | Target domain(s) to find subdomains for    |
| `-dL`      | File containing a list of domains          |
| `-o`       | Save output to a file                      |
| `-oJ`      | Save output in JSON format                 |
| `-silent`  | Show only subdomains (no logs)             |
| `-all`     | Use all sources for enumeration            |
| `-s`       | Specify sources to use                     |
| `-es`      | Exclude specific sources                   |
| `-t`       | Number of concurrent threads               |
| `-timeout` | Timeout in seconds (default 30)            |
| `-v`       | Show verbose output                        |
| `-ls`      | List all available sources                 |
| `-version` | Show subfinder version                     |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `go: command not found` | Go is not installed or not added to PATH |
| `subfinder: command not found` | Use `./subfinder` instead, or move the binary to a directory in your PATH |
| Few results returned | Add API keys to `provider-config.yaml` or use the `-all` flag |
| Build fails | Make sure Go 1.24+ is installed and run `go mod tidy` before building |
