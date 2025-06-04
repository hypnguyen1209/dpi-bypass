package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/things-go/go-socks5"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

// Config represents the YAML configuration structure
type Config struct {
	Socks5 struct {
		ListenAddr string   `yaml:"listen_addr"`
		Username   string   `yaml:"username"`
		Password   string   `yaml:"password"`
		Timeout    int      `yaml:"timeout_seconds"`
	} `yaml:"socks5"`
	Upstream struct {
		Socks5Addr string `yaml:"socks5_addr"`
	} `yaml:"upstream"`
	Domains         []string `yaml:"domains"`
	DomainsRegex    []string `yaml:"domains_regex"` // Domains that are always treated as regex patterns
	CIDRs           []string `yaml:"cidrs"`
	RulesFile       string   `yaml:"rules_file"`
	InverseMode     bool     `yaml:"inverse_mode"`
	ProxyDNS        bool     `yaml:"proxy_dns"`
	FilterHeaders   bool     `yaml:"filter_headers"`
	UseRegex        bool     `yaml:"use_regex"`      // Use regex patterns for domain matching
	DNS struct {
		Server string `yaml:"server"`
	} `yaml:"dns"`
}

// DPIBypassDialer is a custom dialer that can route connections through either direct or SOCKS5 based on domain
type DPIBypassDialer struct {
	targetDomains   []string
	targetCIDRs     []*net.IPNet
	upstreamDialer  proxy.Dialer
	directDialer    proxy.Dialer
	dnsCache        map[string][]string
	cacheMu         sync.RWMutex
	stats           struct {
		proxiedConnections int
		directConnections  int
		cacheHits          int
		ipMatches          int
		lastResetTime      time.Time
		mu                 sync.RWMutex
	}
	dnsServer      string
	verbose        bool
	inverseMode    bool      // If true, routes everything through proxy except specified domains
	timeout        time.Duration
	filterHeaders  bool      // If true, modifies HTTP headers to bypass DPI
	useRegex       bool      // If true, use regex patterns for domain matching
	domainRegexps  []*regexp.Regexp  // Compiled regex patterns for domain matching
}

// parseCIDR parses and validates a CIDR string
func parseCIDR(cidr string) (*net.IPNet, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return network, nil
}

// NewDPIBypassDialer creates a new DPI bypass dialer
func NewDPIBypassDialer(upstreamAddr string, targetDomains []string, targetCIDRs []string, 
                        dnsServer string, inverseMode bool, timeout int, filterHeaders bool, useRegex bool) (*DPIBypassDialer, error) {
	var upstreamDialer proxy.Dialer = proxy.Direct
	var err error

	// Only create SOCKS5 dialer if upstream address is provided
	if upstreamAddr != "" {
		upstreamDialer, err = proxy.SOCKS5("tcp", upstreamAddr, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("creating upstream SOCKS5 dialer: %w", err)
		}
	}

	// Parse CIDRs
	var parsedCIDRs []*net.IPNet
	for _, cidrStr := range targetCIDRs {
		cidr, err := parseCIDR(cidrStr)
		if err != nil {
			log.Printf("Warning: Invalid CIDR %s: %v", cidrStr, err)
			continue
		}
		parsedCIDRs = append(parsedCIDRs, cidr)
	}

	// Compile regex patterns if enabled
	var domainRegexps []*regexp.Regexp
	if useRegex {
		for _, pattern := range targetDomains {
			re, err := regexp.Compile(pattern)
			if err != nil {
				log.Printf("Warning: Invalid regex pattern %s: %v", pattern, err)
				continue
			}
			domainRegexps = append(domainRegexps, re)
		}
	}

	// Set a default timeout if not provided
	timeoutDuration := time.Duration(timeout) * time.Second
	if timeout <= 0 {
		timeoutDuration = 30 * time.Second  // Default: 30 seconds
	}

	dialer := &DPIBypassDialer{
		targetDomains:  targetDomains,
		targetCIDRs:    parsedCIDRs,
		upstreamDialer: upstreamDialer,
		directDialer:   proxy.Direct,
		dnsCache:       make(map[string][]string),
		dnsServer:      dnsServer,
		verbose:        false,
		inverseMode:    inverseMode,
		timeout:        timeoutDuration,
		filterHeaders:  filterHeaders,
		useRegex:       useRegex,
		domainRegexps:  domainRegexps,
	}
	dialer.stats.lastResetTime = time.Now()
	return dialer, nil
}

// SetVerbose sets the verbose logging mode
func (d *DPIBypassDialer) SetVerbose(verbose bool) {
	d.verbose = verbose
}

// ReportStats reports the current statistics
func (d *DPIBypassDialer) ReportStats() {
	d.stats.mu.RLock()
	defer d.stats.mu.RUnlock()
	
	duration := time.Since(d.stats.lastResetTime).Round(time.Second)
	total := d.stats.proxiedConnections + d.stats.directConnections
	
	log.Printf("=== Connection Statistics (%s) ===", duration)
	log.Printf("Total Connections: %d", total)
	if total > 0 {
		log.Printf("Proxied Connections: %d (%.1f%%)", 
			d.stats.proxiedConnections, 
			float64(d.stats.proxiedConnections)*100.0/float64(total))
		log.Printf("Direct Connections: %d (%.1f%%)", 
			d.stats.directConnections, 
			float64(d.stats.directConnections)*100.0/float64(total))
	} else {
		log.Printf("Proxied Connections: 0 (0.0%%)")
		log.Printf("Direct Connections: 0 (0.0%%)")
	}
	log.Printf("IP CIDR Matches: %d", d.stats.ipMatches)
	log.Printf("DNS Cache Hits: %d", d.stats.cacheHits)
	if d.inverseMode {
		log.Printf("Mode: Inverse (default route through proxy)")
	} else {
		log.Printf("Mode: Normal (default direct connection)")
	}
	log.Printf("==============================")
}

// ResetStats resets the statistics counters
func (d *DPIBypassDialer) ResetStats() {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()
	
	d.stats.proxiedConnections = 0
	d.stats.directConnections = 0
	d.stats.cacheHits = 0
	d.stats.lastResetTime = time.Now()
}

// Dial implements the proxy.Dialer interface
func (d *DPIBypassDialer) Dial(network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Check if this is an HTTPS connection (port 443)
	isHTTPS := port == "443"

	// If no upstream proxy is configured, always use direct connection
	if d.upstreamDialer == proxy.Direct {
		if d.verbose {
			log.Printf("No upstream proxy, connecting to %s directly", addr)
		}
		
		d.stats.mu.Lock()
		d.stats.directConnections++
		d.stats.mu.Unlock()
		
		conn, err := d.directDialer.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		
		// If HTTP header filtering is enabled and this is not HTTPS, apply filter
		if d.filterHeaders && !isHTTPS {
			return NewHeaderFilter(conn, isHTTPS, d.verbose), nil
		}
		return conn, nil
	}

	// Determine if we should route through proxy
	shouldProxy := d.inverseMode // In inverse mode, default is to proxy

	// Check if the host is an IP address
	ip := net.ParseIP(host)
	if ip != nil {
		// It's an IP address, check if it matches any of our CIDR ranges
		for _, cidr := range d.targetCIDRs {
			if cidr.Contains(ip) {
				if d.verbose {
					log.Printf("IP %s matches CIDR %s", host, cidr.String())
				}
				shouldProxy = !d.inverseMode // Match means proxy in normal mode, direct in inverse
				
				// Update IP match stats
				d.stats.mu.Lock()
				d.stats.ipMatches++
				d.stats.mu.Unlock()
				break
			}
		}
	} else {
		// It's a domain name, check if it matches our target domains
		if d.useRegex {
			// Use regex pattern matching
			for i, re := range d.domainRegexps {
				if re.MatchString(host) {
					if d.verbose {
						log.Printf("Domain %s matches regex pattern %s", host, d.targetDomains[i])
					}
					shouldProxy = !d.inverseMode // Match means proxy in normal mode, direct in inverse
					break
				}
			}
		} else {
			// Use simple string contains matching
			for _, domain := range d.targetDomains {
				if strings.Contains(host, domain) {
					if d.verbose {
						log.Printf("Domain %s matches pattern %s", host, domain)
					}
					shouldProxy = !d.inverseMode // Match means proxy in normal mode, direct in inverse
					break
				}
			}
		}
	}

	// Apply the routing decision
	if shouldProxy {
		if d.verbose {
			log.Printf("Routing connection to %s through SOCKS5 proxy", addr)
		}
		
		// Update stats
		d.stats.mu.Lock()
		d.stats.proxiedConnections++
		d.stats.mu.Unlock()
		
		// Connect through SOCKS5 proxy with timeout
		if d.timeout > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
			defer cancel()
			
			// Create a channel for the connection result
			type dialResult struct {
				conn net.Conn
				err  error
			}
			result := make(chan dialResult, 1)
			
			go func() {
				conn, err := d.upstreamDialer.Dial(network, addr)
				result <- dialResult{conn, err}
			}()
			
			// Wait for connection or timeout
			select {
			case r := <-result:
				if r.err != nil {
					return nil, r.err
				}
				
				// If HTTP header filtering is enabled and this is not HTTPS, apply filter
				if d.filterHeaders && port != "443" {
					return NewHeaderFilter(r.conn, port == "443", d.verbose), nil
				}
				return r.conn, nil
				
			case <-ctx.Done():
				return nil, fmt.Errorf("connection to %s through proxy timed out after %v", addr, d.timeout)
			}
		} else {
			// No timeout specified
			conn, err := d.upstreamDialer.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			
			// If HTTP header filtering is enabled and this is not HTTPS, apply filter
			if d.filterHeaders && port != "443" {
				return NewHeaderFilter(conn, port == "443", d.verbose), nil
			}
			return conn, nil
		}
	} else {
		if d.verbose {
			log.Printf("Routing connection to %s directly", addr)
		}
		
		// Update stats
		d.stats.mu.Lock()
		d.stats.directConnections++
		d.stats.mu.Unlock()
		
		// Direct connection with timeout
		if d.timeout > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
			defer cancel()
			
			// Create a channel for the connection result
			type dialResult struct {
				conn net.Conn
				err  error
			}
			result := make(chan dialResult, 1)
			
			go func() {
				conn, err := d.directDialer.Dial(network, addr)
				result <- dialResult{conn, err}
			}()
			
			// Wait for connection or timeout
			select {
			case r := <-result:
				if r.err != nil {
					return nil, r.err
				}
				
				// If HTTP header filtering is enabled and this is not HTTPS, apply filter
				if d.filterHeaders && port != "443" {
					return NewHeaderFilter(r.conn, port == "443", d.verbose), nil
				}
				return r.conn, nil
				
			case <-ctx.Done():
				return nil, fmt.Errorf("direct connection to %s timed out after %v", addr, d.timeout)
			}
		}
		
		conn, err := d.directDialer.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		
		// If HTTP header filtering is enabled and this is not HTTPS, apply filter
		if d.filterHeaders && port != "443" {
			return NewHeaderFilter(conn, port == "443", d.verbose), nil
		}
		return conn, nil
	}
}

// lookupIP performs a DNS lookup through the specified DNS server
func (d *DPIBypassDialer) lookupIP(host string) ([]string, error) {
	// Check cache first
	d.cacheMu.RLock()
	ips, found := d.dnsCache[host]
	d.cacheMu.RUnlock()
	
	if found {
		// Update stats
		d.stats.mu.Lock()
		d.stats.cacheHits++
		d.stats.mu.Unlock()
		
		if d.verbose {
			log.Printf("DNS cache hit for %s: %v", host, ips)
		}
		return ips, nil
	}

	// Create a new DNS message
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	// Create a DNS client
	c := new(dns.Client)
	
	// Send the query
	r, _, err := c.Exchange(m, d.dnsServer)
	if err != nil {
		return nil, err
	}

	// Process the answer
	var result []string
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			result = append(result, a.A.String())
		}
	}

	// Cache the result
	if len(result) > 0 {
		d.cacheMu.Lock()
		d.dnsCache[host] = result
		d.cacheMu.Unlock()
		
		if d.verbose {
			log.Printf("DNS lookup for %s: %v", host, result)
		}
	}

	return result, nil
}

// SocksCredentialStore implements the socks5.CredentialStore interface
type SocksCredentialStore struct {
	username string
	password string
}

// Valid validates the provided username and password
func (s *SocksCredentialStore) Valid(username, password, userAddr string) bool {
	return username == s.username && password == s.password
}

// loadRules loads domain and CIDR patterns from an external rules file
func loadRules(path string) ([]string, []string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening rules file: %w", err)
	}
	defer file.Close()

	var domains []string
	var cidrs []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse domain rules
		if strings.HasPrefix(line, "domain:") {
			domain := strings.TrimPrefix(line, "domain:")
			domain = strings.TrimSpace(domain)
			if domain != "" {
				domains = append(domains, domain)
			}
			continue
		}
		
		// Parse regex domain rules
		if strings.HasPrefix(line, "regex:") {
			regex := strings.TrimPrefix(line, "regex:")
			regex = strings.TrimSpace(regex)
			if regex != "" {
				// Validate regex by trying to compile it
				if _, err := regexp.Compile(regex); err != nil {
					log.Printf("Warning: Invalid regex pattern in rules file: %s (%v)", regex, err)
				} else {
					domains = append(domains, regex)
				}
			}
			continue
		}

		// Parse CIDR rules
		if strings.HasPrefix(line, "cidr:") {
			cidr := strings.TrimPrefix(line, "cidr:")
			cidr = strings.TrimSpace(cidr)
			if cidr != "" {
				cidrs = append(cidrs, cidr)
			}
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("reading rules file: %w", err)
	}

	return domains, cidrs, nil
}

// loadConfig loads configuration from a YAML file
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Set defaults for empty values
	if config.DNS.Server == "" {
		config.DNS.Server = "8.8.8.8:53"
	}

	return &config, nil
}

// DNSProxy handles DNS requests, optionally routing them through the upstream proxy
type DNSProxy struct {
	upstreamDNS    string
	targetDomains  []string
	domainRegexps  []*regexp.Regexp
	upstreamDialer proxy.Dialer
	directDialer   proxy.Dialer
	verbose        bool
	inverseMode    bool
	useRegex       bool
}

// NewDNSProxy creates a new DNS proxy
func NewDNSProxy(upstreamDNS string, targetDomains []string, upstreamDialer proxy.Dialer, inverseMode bool, verbose bool, useRegex bool) *DNSProxy {
	var domainRegexps []*regexp.Regexp
	
	// Compile regex patterns if enabled
	if useRegex {
		for _, pattern := range targetDomains {
			re, err := regexp.Compile(pattern)
			if err != nil {
				log.Printf("Warning: Invalid regex pattern %s: %v", pattern, err)
				continue
			}
			domainRegexps = append(domainRegexps, re)
		}
	}
	
	return &DNSProxy{
		upstreamDNS:   upstreamDNS,
		targetDomains: targetDomains,
		domainRegexps: domainRegexps,
		upstreamDialer: upstreamDialer,
		directDialer:   proxy.Direct,
		verbose:       verbose,
		inverseMode:   inverseMode,
		useRegex:      useRegex,
	}
}

// ServeDNS implements the dns.Handler interface
func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	
	if len(r.Question) == 0 {
		w.WriteMsg(msg)
		return
	}
	
	question := r.Question[0]
	domain := question.Name
	
	// Remove trailing dot from domain
	domain = strings.TrimSuffix(domain, ".")
	
	// Determine if we should route through proxy
	shouldProxy := p.inverseMode // In inverse mode, default is to proxy
	
	// Check if the domain matches our target domains
	if p.useRegex {
		// Use regex pattern matching
		for i, re := range p.domainRegexps {
			if re.MatchString(domain) {
				if p.verbose {
					log.Printf("DNS query for %s matches regex pattern %s", domain, p.targetDomains[i])
				}
				shouldProxy = !p.inverseMode // Match means proxy in normal mode, direct in inverse
				break
			}
		}
	} else {
		// Use simple string contains matching
		for _, target := range p.targetDomains {
			if strings.Contains(domain, target) {
				if p.verbose {
					log.Printf("DNS query for %s matches pattern %s", domain, target)
				}
				shouldProxy = !p.inverseMode // Match means proxy in normal mode, direct in inverse
				break
			}
		}
	}
	
	// Choose dialer based on routing decision
	var dialer proxy.Dialer
	if shouldProxy && p.upstreamDialer != proxy.Direct {
		if p.verbose {
			log.Printf("Routing DNS query for %s through proxy", domain)
		}
		dialer = p.upstreamDialer
	} else {
		if p.verbose {
			log.Printf("Routing DNS query for %s directly", domain)
		}
		dialer = p.directDialer
	}
	
	// Create a clone of the query
	query := r.Copy()
	
	// Set up a connection to the upstream DNS server
	var conn net.Conn
	var err error
	
	// Connect with the appropriate dialer
	conn, err = dialer.Dial("tcp", p.upstreamDNS)
	if err != nil {
		log.Printf("Error connecting to DNS server: %v", err)
		msg.Rcode = dns.RcodeServerFailure
		w.WriteMsg(msg)
		return
	}
	defer conn.Close()
	
	// Create a DNS connection
	dnsConn := &dns.Conn{Conn: conn}
	
	// Send the query
	if err := dnsConn.WriteMsg(query); err != nil {
		log.Printf("Error sending DNS query: %v", err)
		msg.Rcode = dns.RcodeServerFailure
		w.WriteMsg(msg)
		return
	}
	
	// Read the response
	resp, err := dnsConn.ReadMsg()
	if err != nil {
		log.Printf("Error reading DNS response: %v", err)
		msg.Rcode = dns.RcodeServerFailure
		w.WriteMsg(msg)
		return
	}
	
	// Send the response back to the client
	w.WriteMsg(resp)
}

// HeaderFilter is a net.Conn wrapper that modifies HTTP headers to bypass DPI
type HeaderFilter struct {
	net.Conn
	buffer         []byte
	headerFiltered bool
	isHTTPS        bool
	verbose        bool
}

// NewHeaderFilter creates a connection wrapper that filters HTTP headers
func NewHeaderFilter(conn net.Conn, isHTTPS bool, verbose bool) *HeaderFilter {
	return &HeaderFilter{
		Conn:           conn,
		buffer:         make([]byte, 0),
		headerFiltered: false,
		isHTTPS:        isHTTPS,
		verbose:        verbose,
	}
}

// Read reads data from the connection and filters HTTP headers if needed
func (f *HeaderFilter) Read(b []byte) (int, error) {
	// If not HTTP or already filtered, read directly
	if f.isHTTPS || f.headerFiltered {
		return f.Conn.Read(b)
	}

	// Read data from the underlying connection
	n, err := f.Conn.Read(b)
	if err != nil {
		return n, err
	}

	// Append to buffer to process headers
	f.buffer = append(f.buffer, b[:n]...)
	
	// Check if we have a complete HTTP header
	headerEnd := bytes.Index(f.buffer, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		// Header not complete, return what we read
		copy(b, f.buffer)
		read := len(f.buffer)
		f.buffer = f.buffer[:0]
		return read, nil
	}

	// We have a complete HTTP header, process it
	header := f.buffer[:headerEnd+4] // Include the \r\n\r\n
	body := f.buffer[headerEnd+4:]
	
	// Apply header filtering
	modifiedHeader := f.filterHeader(header)
	
	// Combine modified header and body
	modified := append(modifiedHeader, body...)
	
	// Copy back to the output buffer
	copyLen := min(len(modified), len(b))
	copy(b, modified[:copyLen])
	
	// If modified data doesn't fit in the output buffer, store the rest
	if copyLen < len(modified) {
		f.buffer = modified[copyLen:]
	} else {
		f.buffer = f.buffer[:0]
	}
	
	f.headerFiltered = true
	return copyLen, nil
}

// filterHeader modifies HTTP headers to bypass DPI
func (f *HeaderFilter) filterHeader(header []byte) []byte {
	headerStr := string(header)
	lines := strings.Split(headerStr, "\r\n")
	
	for i, line := range lines {
		if i == 0 {
			// This is the request line, don't modify
			continue
		}
		
		if line == "" {
			// End of headers
			break
		}
		
		if strings.HasPrefix(line, "Host:") {
			// Leave Host header intact
			continue
		}
		
		if strings.HasPrefix(line, "User-Agent:") {
			// Modify User-Agent to a common browser
			lines[i] = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
			continue
		}
		
		if strings.HasPrefix(line, "Accept:") {
			// Use standard Accept header
			lines[i] = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
			continue
		}
		
		if strings.HasPrefix(line, "Accept-Encoding:") {
			// Use standard encoding
			lines[i] = "Accept-Encoding: gzip, deflate, br"
			continue
		}
		
		if strings.HasPrefix(line, "Accept-Language:") {
			// Use standard language
			lines[i] = "Accept-Language: en-US,en;q=0.9"
			continue
		}
	}
	
	// Rebuild the header
	modifiedHeader := strings.Join(lines, "\r\n")
	
	if f.verbose {
		log.Printf("Modified HTTP headers to bypass DPI")
	}
	
	return []byte(modifiedHeader)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	var (
		listenAddr    = flag.String("listen", "127.0.0.1:1080", "SOCKS5 proxy listen address")
		upstreamAddr  = flag.String("upstream", "", "Upstream SOCKS5 proxy address (optional)")
		username      = flag.String("username", "", "SOCKS5 username (if empty, no auth required)")
		password      = flag.String("password", "", "SOCKS5 password")
		domain        = flag.String("domain", "", "Domain to bypass DPI for")
		domainRegex   = flag.String("domains-regex", "", "Regex pattern for domains to bypass DPI for")
		cidr          = flag.String("cidr", "", "CIDR notation for IP ranges to bypass DPI for")
		dnsServer     = flag.String("dns", "8.8.8.8:53", "DNS server for lookups")
		configPath    = flag.String("config", "", "Path to YAML configuration file")
		verbose       = flag.Bool("verbose", false, "Enable verbose logging")
		statsInterval = flag.Int("stats", 0, "Statistics reporting interval in seconds (0 to disable)")
		inverseMode   = flag.Bool("inverse", false, "Inverse mode: route everything through proxy except specified domains")
		timeout       = flag.Int("timeout", 30, "Connection timeout in seconds (0 to disable)")
	)

	flag.Parse()

	// Default configuration
	var config Config
	config.Socks5.ListenAddr = *listenAddr
	config.Socks5.Username = *username
	config.Socks5.Password = *password
	config.Socks5.Timeout = *timeout
	config.Upstream.Socks5Addr = *upstreamAddr
	config.DNS.Server = *dnsServer
	config.InverseMode = *inverseMode
	
	// Try to load from config file if specified
	if *configPath != "" {
		log.Printf("Loading configuration from %s", *configPath)
		loadedConfig, err := loadConfig(*configPath)
		if err != nil {
			log.Printf("Warning: Failed to load config file: %v", err)
		} else {
			config = *loadedConfig
		}
	}
	
	// Load external rules file if specified
	if config.RulesFile != "" {
		log.Printf("Loading rules from %s", config.RulesFile)
		domains, cidrs, err := loadRules(config.RulesFile)
		if err != nil {
			log.Printf("Warning: Failed to load rules file: %v", err)
		} else {
			if len(domains) > 0 {
				log.Printf("Loaded %d domain rules from rules file", len(domains))
				config.Domains = append(config.Domains, domains...)
			}
			if len(cidrs) > 0 {
				log.Printf("Loaded %d CIDR rules from rules file", len(cidrs))
				config.CIDRs = append(config.CIDRs, cidrs...)
			}
		}
	}
	
	// Command line arguments override config file
	if *listenAddr != "127.0.0.1:1080" {
		config.Socks5.ListenAddr = *listenAddr
	}
	if *upstreamAddr != "" {
		config.Upstream.Socks5Addr = *upstreamAddr
	}
	if *username != "" {
		config.Socks5.Username = *username
	}
	if *password != "" {
		config.Socks5.Password = *password
	}
	if *domain != "" {
		config.Domains = append(config.Domains, *domain)
	}
	if *domainRegex != "" {
		config.DomainsRegex = append(config.DomainsRegex, *domainRegex)
	}
	if *cidr != "" {
		config.CIDRs = append(config.CIDRs, *cidr)
	}
	if *dnsServer != "8.8.8.8:53" {
		config.DNS.Server = *dnsServer
	}
	// Always apply command line flags for these options
	config.InverseMode = *inverseMode
	config.Socks5.Timeout = *timeout

	// Ensure we have at least one domain (either regular or regex)
	if len(config.Domains) == 0 && len(config.DomainsRegex) == 0 {
		log.Fatal("Please specify at least one domain to bypass DPI for using -domain, -domains-regex, or in the config file")
	}

	// Load additional rules from file if specified
	if config.RulesFile != "" {
		log.Printf("Loading rules from file: %s", config.RulesFile)
		domains, cidrs, err := loadRules(config.RulesFile)
		if err != nil {
			log.Printf("Warning: Failed to load rules from file: %v", err)
		} else {
			config.Domains = append(config.Domains, domains...)
			config.CIDRs = append(config.CIDRs, cidrs...)
		}
	}

	// Combine regular domains and regex domains
	allDomains := append([]string{}, config.Domains...)
	if len(config.DomainsRegex) > 0 {
		log.Printf("Adding %d regex domain patterns", len(config.DomainsRegex))
		allDomains = append(allDomains, config.DomainsRegex...)
		// If we have regex domains, always enable regex mode
		config.UseRegex = true
	}

	// Create custom dialer with DPI bypass logic
	dpiDialer, err := NewDPIBypassDialer(
		config.Upstream.Socks5Addr, 
		allDomains, 
		config.CIDRs, 
		config.DNS.Server,
		config.InverseMode,
		config.Socks5.Timeout,
		config.FilterHeaders,
		config.UseRegex,
	)
	if err != nil {
		log.Fatalf("Failed to create DPI bypass dialer: %v", err)
	}
	dpiDialer.SetVerbose(*verbose)

	// SOCKS5 server options
	opts := []socks5.Option{
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithResolver(&socks5.DNSResolver{}),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dpiDialer.Dial(network, addr)
		}),
	}
	
	// Add authentication if provided
	if config.Socks5.Username != "" && config.Socks5.Password != "" {
		creds := &SocksCredentialStore{
			username: config.Socks5.Username,
			password: config.Socks5.Password,
		}
		opts = append(opts, socks5.WithAuthMethods([]socks5.Authenticator{
			socks5.UserPassAuthenticator{Credentials: creds},
		}))
	}

	// Create SOCKS5 server
	server := socks5.NewServer(opts...)

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up statistics reporting if enabled
	if *statsInterval > 0 {
		go func() {
			interval := time.Duration(*statsInterval) * time.Second
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			
			for {
				select {
				case <-ticker.C:
					dpiDialer.ReportStats()
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	
	// Set up DNS proxy if enabled
	if config.ProxyDNS {
		// Create DNS proxy handler
		dnsProxy := NewDNSProxy(
			config.DNS.Server,
			allDomains, // Use the combined domains list that includes regex patterns
			dpiDialer.upstreamDialer,
			config.InverseMode,
			*verbose,
			config.UseRegex,
		)
		
		// Create DNS server
		dnsServer := &dns.Server{
			Addr:    "127.0.0.1:53",
			Net:     "udp",
			Handler: dnsProxy,
		}
		
		// Start DNS server
		log.Printf("Starting DNS proxy on %s", dnsServer.Addr)
		go func() {
			if err := dnsServer.ListenAndServe(); err != nil {
				log.Printf("DNS server error: %v", err)
			}
		}()
		
		// Graceful shutdown for DNS server
		go func() {
			<-ctx.Done()
			dnsServer.Shutdown()
		}()
	}

	// Set up signal handling for graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down server...")
		// Print final statistics report on shutdown
		dpiDialer.ReportStats()
		cancel()
	}()

	// Start server
	log.Printf("DPI Bypass SOCKS5 Proxy started")
	log.Printf("Listening on %s", config.Socks5.ListenAddr)
	
	if config.Upstream.Socks5Addr != "" {
		log.Printf("Upstream SOCKS5 proxy: %s", config.Upstream.Socks5Addr)
		if config.InverseMode {
			log.Printf("Operating in INVERSE mode: routing ALL traffic through proxy EXCEPT specified rules")
		} else {
			log.Printf("Operating in NORMAL mode: routing ONLY matching traffic through proxy")
		}
		if len(config.Domains) > 0 {
			log.Printf("Domain patterns: %v", config.Domains)
		}
		if len(config.CIDRs) > 0 {
			log.Printf("CIDR patterns: %v", config.CIDRs)
		}
	} else {
		log.Printf("No upstream proxy specified, operating in direct connection mode")
		log.Printf("All rules will be ignored")
	}
	
	log.Printf("Connection timeout: %d seconds", config.Socks5.Timeout)
	
	if config.UseRegex {
		log.Printf("Regex pattern matching is enabled")
	}
	
	listener, err := net.Listen("tcp", config.Socks5.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	if err := server.Serve(listener); err != nil && ctx.Err() == nil {
		log.Fatalf("Server error: %v", err)
	}
}
