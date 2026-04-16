package domain

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"osint/internal/core"
)

// Pre-allocated takeover patterns as slice for faster iteration
var takeoverPatterns = []struct {
	pattern string
	service string
}{
	{"s3.amazonaws.com", "AWS S3 bucket"},
	{"s3-website", "AWS S3 website"},
	{"github.io", "GitHub Pages"},
	{"github.com", "GitHub Pages (legacy)"},
	{"herokuapp.com", "Heroku"},
	{"herokussl.com", "Heroku SSL"},
	{"wordpress.com", "WordPress.com"},
	{"shopify.com", "Shopify"},
	{"fastly.net", "Fastly"},
	{"fastly.com", "Fastly"},
	{"cloudfront.net", "AWS CloudFront"},
	{"azurewebsites.net", "Azure Websites"},
	{"azurestaticapps.net", "Azure Static Apps"},
	{"blob.core.windows.net", "Azure Blob Storage"},
	{"unbouncepages.com", "Unbounce"},
	{"zendesk.com", "Zendesk"},
	{"bitbucket.io", "Bitbucket"},
	{"ghost.io", "Ghost"},
	{"firebaseapp.com", "Firebase"},
	{"web.app", "Firebase Hosting"},
	{"surge.sh", "Surge.sh"},
	{"netlify.app", "Netlify"},
	{"vercel.app", "Vercel"},
	{"pages.dev", "Cloudflare Pages"},
	{"readthedocs.io", "ReadTheDocs"},
	{"statuspage.io", "Statuspage"},
}

// Shared HTTP client with connection pooling
var sharedClient = &http.Client{
	Timeout: 25 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// Shared DNS resolver with caching capability
var sharedResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, network, address)
	},
}

// Run executes domain enumeration and takeover detection
func Run(query string) (core.Result, error) {
	domain := strings.ToLower(strings.TrimSpace(query))
	if !isValidDomain(domain) {
		err := core.NewUserError("invalid domain format (expected: example.com)")
		return core.Fail(core.KindDomain, domain, err), err
	}

	r := core.NewBaseResult(core.KindDomain, domain)
	r.Domain.Domain = domain

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// 1. Enumerate subdomains via crt.sh
	subdomains, err := enumerateFromCRTSH(ctx, domain)
	if err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("crt.sh enumeration failed: %v", err))
		subdomains = []string{domain}
	}

	subdomains = deduplicateAndLimit(subdomains, domain, 50)

	// 2. Analyze concurrently with sync.WaitGroup (cleaner than manual counting)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)
	infoChan := make(chan core.SubdomainInfo, len(subdomains))

	for _, sub := range subdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			info := analyzeSubdomain(subdomain)
			infoChan <- info
		}(sub)
	}

	// Close channel when all workers done
	go func() {
		wg.Wait()
		close(infoChan)
	}()

	// Collect results with timeout
	var infos []core.SubdomainInfo
	collectCtx, collectCancel := context.WithTimeout(ctx, 85*time.Second)
	defer collectCancel()

	for info := range infoChan {
		select {
		case <-collectCtx.Done():
			r.Warnings = append(r.Warnings, "Timeout reached, some subdomains may not have been analyzed")
			goto Done
		default:
			infos = append(infos, info)
		}
	}

Done:
	r.Domain.Subdomains = infos
	r.Sources = []string{"crt.sh", "DNS resolution", "SSL certificate check", "CNAME analysis"}
	return r, nil
}

// enumerateFromCRTSH queries crt.sh for certificate transparency logs
func enumerateFromCRTSH(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "osintmaster/1.0")

	resp, err := sharedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", resp.StatusCode)
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	// Pre-allocate map with expected size
	seen := make(map[string]struct{}, len(entries)*2)
	subs := make([]string, 0, len(entries))

	for _, e := range entries {
		// Fast path: single name (no newline)
		if !strings.Contains(e.NameValue, "\n") {
			name := cleanName(e.NameValue, domain)
			if name != "" {
				if _, exists := seen[name]; !exists {
					seen[name] = struct{}{}
					subs = append(subs, name)
				}
			}
			continue
		}

		// Slow path: multiple names
		names := strings.Split(e.NameValue, "\n")
		for _, name := range names {
			name = cleanName(name, domain)
			if name != "" {
				if _, exists := seen[name]; !exists {
					seen[name] = struct{}{}
					subs = append(subs, name)
				}
			}
		}
	}

	return subs, nil
}

// cleanName normalizes and validates a subdomain name
func cleanName(name, domain string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimPrefix(name, "*.")
	if name == "" || !strings.HasSuffix(name, domain) {
		return ""
	}
	return name
}

// deduplicateAndLimit cleans list and limits to max items
func deduplicateAndLimit(subs []string, rootDomain string, max int) []string {
	seen := make(map[string]struct{}, max)
	result := make([]string, 0, max)

	// Always include root domain first
	if isValidSubdomain(rootDomain) {
		seen[rootDomain] = struct{}{}
		result = append(result, rootDomain)
	}

	for _, sub := range subs {
		sub = strings.ToLower(strings.TrimSpace(sub))
		if sub == "" {
			continue
		}
		if _, exists := seen[sub]; exists {
			continue
		}
		seen[sub] = struct{}{}
		result = append(result, sub)
		if len(result) >= max {
			break
		}
	}
	return result
}

// analyzeSubdomain performs analysis (timeouts handled per-operation)
func analyzeSubdomain(subdomain string) core.SubdomainInfo {
	info := core.SubdomainInfo{
		Name:         subdomain,
		TakeoverRisk: "none",
	}

	// DNS resolution with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Parallel DNS lookups
	var wg sync.WaitGroup
	var cname, ip string
	var cnameErr, ipErr error

	wg.Add(2)

	// CNAME lookup
	go func() {
		defer wg.Done()
		var cn string
		cn, cnameErr = sharedResolver.LookupCNAME(ctx, subdomain)
		cname = strings.TrimSuffix(cn, ".")
	}()

	// IP lookup
	go func() {
		defer wg.Done()
		var ips []string
		ips, ipErr = sharedResolver.LookupHost(ctx, subdomain)
		if len(ips) > 0 {
			ip = ips[0]
		}
	}()

	wg.Wait()
	cancel()

	info.IP = ip
	info.CNAME = cname

	// SSL check (only if IP resolved)
	if ip != "" && ipErr == nil {
		checkSSL(subdomain, ip, &info)
	}

	// Takeover check (only if CNAME different from subdomain)
	if cname != "" && cname != subdomain && cnameErr == nil {
		checkTakeover(cname, &info)
	}

	return info
}

// checkSSL attempts SSL connection with timeout
func checkSSL(subdomain, ip string, info *core.SubdomainInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         subdomain,
		InsecureSkipVerify: true,
	})

	// Single deadline for entire handshake
	deadline := time.Now().Add(3 * time.Second)
	tlsConn.SetDeadline(deadline)

	if err := tlsConn.Handshake(); err != nil {
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		info.SSLValid = true
		info.SSLExpiry = state.PeerCertificates[0].NotAfter.Format("2006-01-02")
	}
}

// checkTakeover detects dangling CNAME records
func checkTakeover(cname string, info *core.SubdomainInfo) {
	for _, tp := range takeoverPatterns {
		if strings.Contains(cname, tp.pattern) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, err := sharedResolver.LookupHost(ctx, cname)
			cancel()

			if err != nil {
				info.TakeoverRisk = fmt.Sprintf("CNAME record points to a non-existent %s (%s)", tp.service, cname)
			}
			return // Found match, stop checking
		}
	}
}

// isValidDomain performs basic domain validation
func isValidDomain(d string) bool {
	// Fast path checks
	if len(d) < 4 || len(d) > 253 {
		return false
	}

	// Strip common prefixes/suffixes
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "www.")
	d = strings.TrimSuffix(d, "/")

	if !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	return true
}

// isValidSubdomain checks if string is valid subdomain format
func isValidSubdomain(s string) bool {
	return s != "" && !strings.HasPrefix(s, ".") && !strings.HasSuffix(s, ".")
}