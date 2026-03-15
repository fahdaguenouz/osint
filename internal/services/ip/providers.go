package ip

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Provider interface for IP geolocation
type Provider interface {
	Lookup(ctx context.Context, ip string) (ISP, City, Country, ASN string, Lat, Lon float64, Source string, err error)
}

// IPAPIProvider uses ip-api.com (free tier: 45 requests/minute, no API key)
type IPAPIProvider struct {
	client *http.Client
}

func NewIPAPIProvider() *IPAPIProvider {
	return &IPAPIProvider{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

type ipAPIResp struct {
	Status  string  `json:"status"`
	Message string  `json:"message"`
	Query   string  `json:"query"`
	City    string  `json:"city"`
	Country string  `json:"country"`
	ISP     string  `json:"isp"`
	ASN     string  `json:"as"` // ASN format: "AS15169 Google LLC"
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

func (p *IPAPIProvider) Lookup(ctx context.Context, ip string) (string, string, string, string, float64, float64, string, error) {
	// Request additional fields: country and ASN
	// Fields: status,message,query,city,country,isp,as,lat,lon
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,query,city,country,isp,as,lat,lon", ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", "", "", 0, 0, "ip-api.com", err
	}
	req.Header.Set("User-Agent", "osintmaster/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", "", "", "", 0, 0, "ip-api.com", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", "", 0, 0, "ip-api.com", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var data ipAPIResp
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", "", "", 0, 0, "ip-api.com", err
	}

	if data.Status != "success" {
		if data.Message == "" {
			data.Message = "lookup failed"
		}
		return "", "", "", "", 0, 0, "ip-api.com", fmt.Errorf("%s", data.Message)
	}

	return data.ISP, data.City, data.Country, data.ASN, data.Lat, data.Lon, "ip-api.com", nil
}

// AbuseIPDBProvider checks IP reputation (free tier: 1000 checks/day, requires API key)
type AbuseIPDBProvider struct {
	apiKey string
	client *http.Client
}

func NewAbuseIPDBProvider() *AbuseIPDBProvider {
	return &AbuseIPDBProvider{
		apiKey: os.Getenv("ABUSEIPDB_API_KEY"), // Optional: tool works without it
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

type abuseIPDBResp struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		TotalReports         int    `json:"totalReports"`
		LastReportedAt       string `json:"lastReportedAt"`
	} `json:"data"`
}

// CheckIP returns abuse score (0-100), report count, last reported date, and source
func (p *AbuseIPDBProvider) CheckIP(ctx context.Context, ip string) (int, int, string, string, error) {
	if p.apiKey == "" {
		return 0, 0, "", "abuseipdb.com", fmt.Errorf("no API key configured (set ABUSEIPDB_API_KEY for enhanced abuse checking)")
	}

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, "", "abuseipdb.com", err
	}

	req.Header.Set("Key", p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, 0, "", "abuseipdb.com", err
	}
	defer resp.Body.Close()

	// Handle rate limiting
	if resp.StatusCode == 429 {
		return 0, 0, "", "abuseipdb.com", fmt.Errorf("rate limit exceeded (free tier: 1000 checks/day)")
	}

	if resp.StatusCode != http.StatusOK {
		return 0, 0, "", "abuseipdb.com", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result abuseIPDBResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, 0, "", "abuseipdb.com", err
	}

	data := result.Data
	return data.AbuseConfidenceScore, data.TotalReports, data.LastReportedAt, "abuseipdb.com", nil
}