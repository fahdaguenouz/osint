package ip

import (
	"context"
	"fmt"
	"strings"
	"time"

	"osint/internal/core"
	"osint/internal/detect"
)

func Run(query string) (core.Result, error) {
	q := strings.TrimSpace(query)

	if !detect.IsIPv4(q) {
		err := core.NewUserError("invalid IPv4 address")
		return core.Fail(core.KindIP, q, err), err
	}

	r := core.NewBaseResult(core.KindIP, q)

	// Create context with timeout for all operations
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Get geolocation data from ip-api.com (free, no key required)
	geoProvider := NewIPAPIProvider()
	isp, city, country, asn, lat, lon, geoSource, err := geoProvider.Lookup(ctx, q)
	if err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("Geolocation lookup failed: %v", err))
	}
	r.Sources = append(r.Sources, geoSource)

	// 2. Check abuse reputation from AbuseIPDB (optional, requires API key)
	abuseProvider := NewAbuseIPDBProvider()
	abuseScore, abuseReports, lastReported, abuseSource, abuseErr := abuseProvider.CheckIP(ctx, q)
	if abuseErr != nil {
		// Only warn, don't fail - this is optional enhancement
		r.Warnings = append(r.Warnings, fmt.Sprintf("Abuse check skipped: %v", abuseErr))
	} else {
		r.Sources = append(r.Sources, abuseSource)
	}

	// Build the result
	r.IP = core.IPResult{
		IP:           q,
		ISP:          isp,
		City:         city,
		Country:      country,
		ASN:          asn,
		Lat:          lat,
		Lon:          lon,
		AbuseScore:   abuseScore,
		AbuseReports: abuseReports,
	}

	// Format known issues message
	if abuseErr != nil || abuseScore == 0 {
		r.IP.KnownIssues = "No reported abuse"
	} else {
		r.IP.KnownIssues = fmt.Sprintf("Abuse confidence: %d%% (%d reports)", abuseScore, abuseReports)
		if lastReported != "" {
			r.IP.KnownIssues += fmt.Sprintf(", last reported: %s", lastReported)
		}
	}

	return r, nil
}
