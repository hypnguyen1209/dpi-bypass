# DPI Bypass

- Inverse mode: route everything through proxy except specified domains/CIDRs
- Support for regex pattern matching for domains
- DNS caching for performance
- Detailed statistics reporting
- Cross-platform support (Linux, macOS, Windows)CKS5 Proxy

A lightweight SOCKS5 proxy that selectively routes traffic for specific domains through an optional upstream SOCKS5 proxy to bypass Deep Packet Inspection (DPI). Can also operate without an upstream proxy as a regular SOCKS5 server.

## Features

- Bypass DPI for specified domains by routing through an upstream SOCKS5 proxy (if provided)
- Can operate with or without an upstream proxy
- Acts as a SOCKS5 proxy server with optional authentication
- Smart routing based on domain patterns and IP CIDR notation
- Connection timeout support prevents hanging connections
- Inverse mode: route everything through proxy except specified domains/CIDRs
- DNS caching for performance
- Detailed statistics reporting
- Cross-platform support (Linux, macOS, Windows)

## Prerequisites

- Go 1.18 or later (for building)
- Optional: An upstream SOCKS5 proxy server (such as Shadowsocks, V2Ray, etc.) for routing bypass traffic

## Building

Use the provided build script to compile for all supported platforms:

```bash
./build.sh
```

This will create binaries for different platforms in the `build/` directory.

Alternatively, build for your current platform:

```bash
go build -o dpi-bypass .
```

## Usage

```bash
# Basic usage with upstream SOCKS5 on localhost:1081
./dpi-bypass -upstream 127.0.0.1:1081 -domain example.com

# Use as regular SOCKS5 server without upstream proxy
./dpi-bypass -domain example.com

# Specify custom listen address
./dpi-bypass -listen 127.0.0.1:1082 -domain example.com

# Use IP CIDR notation for routing decisions
./dpi-bypass -upstream 127.0.0.1:1081 -cidr 192.168.1.0/24

# Use inverse mode - route everything through proxy except specified domains
./dpi-bypass -upstream 127.0.0.1:1081 -domain example.com -inverse

# Set custom connection timeout
./dpi-bypass -upstream 127.0.0.1:1081 -domain example.com -timeout 60

# Use authentication
./dpi-bypass -username user1 -password pass123 -domain example.com

# Use regex pattern matching for domains with the new -domains-regex flag
./dpi-bypass -upstream 127.0.0.1:1081 -domains-regex "^.*\\.google\\.com$"

# Use a configuration file
./dpi-bypass -config config.yml

# Enable verbose logging and statistics reporting
./dpi-bypass -domain example.com -verbose -stats 30
```

### Command-line options

- `-listen`: SOCKS5 proxy listen address (default: 127.0.0.1:1080)
- `-domain`: Domain to bypass DPI for (required if not in config file)
- `-domains-regex`: Regex pattern for domains to bypass DPI for
- `-upstream`: Upstream SOCKS5 proxy address (default: 127.0.0.1:1081)
- `-username`: SOCKS5 server username (optional)
- `-password`: SOCKS5 server password (optional)
- `-dns`: DNS server for lookups (default: 8.8.8.8:53)
- `-config`: Path to YAML configuration file
- `-verbose`: Enable verbose logging
- `-stats`: Statistics reporting interval in seconds (0 to disable)

## How It Works

1. The tool runs as a local DNS server
2. DNS queries for the specified domain are routed through the SOCKS5 proxy
3. Responses are cached to improve performance
4. All other domain queries are forwarded directly to public DNS servers

## Configuration File

The tool supports configuration through a YAML file. Example:

```yaml
# DPI Bypass SOCKS5 Proxy Configuration
socks5:
  listen_addr: "0.0.0.0:10900"
  username: ""  # Optional, leave empty for no authentication
  password: ""  # Optional, leave empty for no authentication
  timeout_seconds: 30  # Connection timeout in seconds (0 to disable)

upstream:
  socks5_addr: "127.0.0.1:1081"  # Upstream SOCKS5 proxy address

# DNS settings
dns:
  server: "8.8.8.8:53"

# Routing mode
inverse_mode: false


# Target domains for routing (substring matching by default)
domains:
  - example.com
  - restricted-site.com

# Target domains with regex patterns (always treated as regex regardless of use_regex)
domains_regex:
  - "^.*\\.google\\.com$"
  - "^api\\..*\\.com$"

# Target IP ranges for routing (CIDR notation)
cidrs:
  - "192.168.1.0/24" 
  - "10.0.0.0/8"

# External rules file path
rules_file: "rules.txt"
```

## Rules File Format

The rules file allows specifying domains and CIDRs in a simple text format:

```
# Comments start with #

# Domain rules (substring matching)
domain:example.com
domain:restricted-site.org

# Regex rules (regular expression matching)
# Note: Regex mode is automatically enabled when regex patterns are provided
regex:^.*\\.google\\.com$
regex:^api\\..*\\.com$

# CIDR rules (IP range matching)
cidr:192.168.1.0/24
cidr:10.0.0.0/8
```

## Use Cases

- Circumvent DNS-based censorship
- Avoid domain-based traffic throttling
- Use regex patterns for more sophisticated domain matching
- Test network connectivity through proxies

## License

MIT
