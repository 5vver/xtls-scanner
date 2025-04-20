# XTLS Scanner

## Run or build

```bash
# Run locally
go run *.go
# Or simply build to executable
go build
```

## Usage

Run tls scanner locally to save your VPS address from being flagged

```bash
# Get help
./xtls-scanner

# Provide IP, CIDR or Hostname to ping
./xtls-scanner -host host.exmple -ping

# Set ping timeout amount (Default: 5)
./xtls-scanner -host host.exmple -ping -timeout 2

# Scan tls and enable crawl mode to look for subdomains starting from host target (if got handshake from host - automatically ping this host)
./xtls-scanner -host host.exmple -tls

# Specify tls crawl depth (Default: 10)
./xtls-scanner -host host.exmple -tls -depth 20

# Specify result file name
./xtls-scanner -host host.exmple -tls -out result.txt
```
