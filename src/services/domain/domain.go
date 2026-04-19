package domain

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"osint/src/core"
)

// ================= TAKEOVER PATTERNS =================

var takeoverPatterns = []struct {
	pattern string
	service string
}{
	{"s3.amazonaws.com", "AWS S3 bucket"},
	{"s3-website", "AWS S3 website"},
	{"github.io", "GitHub Pages"},
	{"herokuapp.com", "Heroku"},
	{"wordpress.com", "WordPress.com"},
	{"shopify.com", "Shopify"},
	{"fastly.net", "Fastly"},
	{"cloudfront.net", "AWS CloudFront"},
	{"azurewebsites.net", "Azure Websites"},
	{"firebaseapp.com", "Firebase"},
	{"netlify.app", "Netlify"},
	{"vercel.app", "Vercel"},
	{"pages.dev", "Cloudflare Pages"},
}

// ================= GLOBALS =================

var client = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	},
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// ================= MAIN =================

func Run(query string) (core.Result, error) {
	domain := cleanDomain(query)

	if !isValidDomain(domain) {
		err := fmt.Errorf("invalid domain format")
		return core.Fail(core.KindDomain, domain, err), err
	}

	r := core.NewBaseResult(core.KindDomain, domain)
	r.Domain.Domain = domain

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var allSubs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Source runner helper
	runSource := func(name string, fn func(context.Context, string) ([]string, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := fn(ctx, domain)
			if err != nil {
				mu.Lock()
				r.Warnings = append(r.Warnings, fmt.Sprintf("%s skipped/failed: %v", name, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			allSubs = append(allSubs, subs...)
			mu.Unlock()
		}()
	}

	// ✅ ONLY 3 RELIABLE SOURCES
	runSource("crt.sh", crtsh)              // Certificate transparency logs
	runSource("hackertarget", hackertarget) // DNS enumeration
	runSource("anubis", anubis)             // Subdomain database

	wg.Wait()

	// Append brute force guesses
	allSubs = append(allSubs, bruteForce(domain)...)

	// Clean the master list
	allSubs = deduplicate(allSubs, domain)

	return buildResult(ctx, r, allSubs), nil
}

// ================= BUILD RESULT =================

func buildResult(ctx context.Context, r core.Result, subs []string) core.Result {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 25)
	out := make(chan core.SubdomainInfo, len(subs))

	for _, sub := range subs {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			out <- analyze(ctx, s)
			<-sem
		}(sub)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	for info := range out {
		if info.IP != "" || info.CNAME != "" {
			r.Domain.Subdomains = append(r.Domain.Subdomains, info)
		}
	}

	r.Sources = []string{"3 Public APIs", "Brute Force", "DNS Resolution", "SSL check"}
	return r
}

// ================= ANALYZE =================

func analyze(parentCtx context.Context, sub string) core.SubdomainInfo {
	info := core.SubdomainInfo{
		Name:         sub,
		TakeoverRisk: "none",
	}

	ctx, cancel := context.WithTimeout(parentCtx, 4*time.Second)
	defer cancel()

	cname, _ := net.DefaultResolver.LookupCNAME(ctx, sub)
	cname = strings.TrimSuffix(cname, ".")
	if cname != sub && cname != "" {
		info.CNAME = cname
	}

	ips, _ := net.DefaultResolver.LookupHost(ctx, sub)
	if len(ips) > 0 {
		info.IP = ips[0]
		checkSSL(sub, ips[0], &info)
	}

	if info.CNAME != "" {
		checkTakeover(parentCtx, info.CNAME, &info)
	}

	return info
}

// ================= TAKEOVER LOGIC =================

func checkTakeover(ctx context.Context, cname string, info *core.SubdomainInfo) {
	for _, tp := range takeoverPatterns {
		if strings.Contains(cname, tp.pattern) {
			lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, err := net.DefaultResolver.LookupHost(lookupCtx, cname)
			cancel()

			if err != nil {
				info.TakeoverRisk = fmt.Sprintf("CNAME points to non-existent %s (%s)", tp.service, cname)
			}
			return
		}
	}
}

// ================= SSL =================

func checkSSL(sub, ip string, info *core.SubdomainInfo) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sub,
		InsecureSkipVerify: true,
	})

	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := tlsConn.Handshake(); err == nil {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			info.SSLValid = true
			info.SSLExpiry = state.PeerCertificates[0].NotAfter.Format("2006-01-02")
		}
	}
}

// ================= HELPERS =================

func deduplicate(list []string, root string) []string {
	seen := map[string]struct{}{root: {}}
	out := []string{root}

	for _, v := range list {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" || !strings.HasSuffix(v, root) {
			continue
		}
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

func cleanDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "www.")
	d = strings.TrimSuffix(d, "/")
	return d
}

func isValidDomain(d string) bool {
	if len(d) < 4 || !strings.Contains(d, ".") {
		return false
	}
	return true
}

func bruteForce(domain string) []string {
	wordlist := []string{
		"www", "mail", "api", "dev", "test", "admin", "beta", "staging", "prod", "app",
		"portal", "auth", "cdn", "static", "blog", "shop", "support", "docs", "ftp",
		"vpn", "secure", "git", "jenkins", "gitlab", "jira", "db", "sql", "redis",
		"s3", "backup", "demo", "sandbox", "internal", "mobile", "media", "video",
		"ws", "chat", "monitor", "status", "health", "grafana", "kibana", "webmail",
	}
	var out []string
	for _, w := range wordlist {
		out = append(out, w+"."+domain)
	}
	return out
}

// ================= API SOURCES (Only 3) =================

func crtsh(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var data []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var subs []string
	for _, d := range data {
		for _, name := range strings.Split(d.NameValue, "\n") {
			name = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(name)), "*.")
			if strings.HasSuffix(name, domain) {
				subs = append(subs, name)
			}
		}
	}
	return subs, nil
}

func hackertarget(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var subs []string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) > 0 && strings.HasSuffix(parts[0], domain) {
			subs = append(subs, parts[0])
		}
	}
	return subs, nil
}

func anubis(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var data []string
	json.NewDecoder(resp.Body).Decode(&data)
	return data, nil
}
