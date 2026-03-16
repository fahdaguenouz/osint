package username

import (
	"context"
	"net/http"
	"strings"
	"time"

	"osint/internal/core"
	"osint/internal/detect"
)

func Run(query string) (core.Result, error) {
	q := strings.TrimSpace(query)
	if !detect.IsUsername(q) {
		err := core.NewUserError("invalid username format")
		return core.Fail(core.KindUsername, q, err), err
	}

	handle := strings.TrimPrefix(q, "@")

	r := core.NewBaseResult(core.KindUsername, q)
	r.Username.Username = handle

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't auto-follow redirects
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	results := make([]core.NetworkResult, 0, len(DefaultNetworks))
	var activePlatforms []string

	for _, netw := range DefaultNetworks {
		url := netw.URL(handle)

		found, profileInfo, followers, lastActive, warn := checkProfileDetailed(ctx, client, netw.Name, url, handle)
		if warn != "" {
			r.Warnings = append(r.Warnings, warn)
		}

		if found {
			activePlatforms = append(activePlatforms, netw.Name)
		}

		results = append(results, core.NetworkResult{
			Name:        netw.Name,
			URL:         url,
			Found:       found,
			ProfileInfo: profileInfo,
			Followers:   followers,
			LastActive:  lastActive,
		})
	}

	// Generate activity summary
	if len(activePlatforms) > 0 {
		r.Username.RecentActivity = "Active on: " + strings.Join(activePlatforms, ", ")
	} else {
		r.Username.RecentActivity = "No recent activity detected"
	}

	r.Username.Networks = results
	r.Sources = append(r.Sources, "direct HTTP check + HTML fingerprint")

	return r, nil
}