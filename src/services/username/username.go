package username

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"osint/src/core"
	"osint/src/detect"

	"github.com/playwright-community/playwright-go"
)

// ==========================================
// 1. MAIN CONCURRENT EXECUTION
// ==========================================

func Run(query string) (core.Result, error) {
	q := strings.TrimSpace(query)
	if !detect.IsUsername(q) {
		err := core.NewUserError("invalid username format")
		return core.Fail(core.KindUsername, q, err), err
	}

	handle := strings.TrimPrefix(q, "@")
	r := core.NewBaseResult(core.KindUsername, q)
	r.Username.Username = handle

	// 1. Initialize Standard HTTP Client (for open APIs)
	client := &http.Client{
		Timeout: 12 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 2. Initialize Playwright (for JS-heavy SPAs like Instagram)
	pw, err := playwright.Run()
	if err != nil {
		return r, fmt.Errorf("could not start playwright: %v", err)
	}
	defer pw.Stop()

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(false), // set false for debugging
		Args: []string{
			"--disable-blink-features=AutomationControlled",
		},
	})
	if err != nil {
		return r, fmt.Errorf("could not launch browser: %v", err)
	}
	defer browser.Close()

	bCtx, err := browser.NewContext(playwright.BrowserNewContextOptions{
		UserAgent:  playwright.String("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"),
		Viewport:   &playwright.Size{Width: 1280, Height: 720},
		Locale:     playwright.String("en-US"),
		TimezoneId: playwright.String("Europe/Paris"),
	})
	if err != nil {
		return r, err
	}
	defer bCtx.Close()

	// 3. Execution Context
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results := make([]core.NetworkResult, 0, len(DefaultNetworks))
	var activePlatforms []string
	var allPosts []core.Post

	// 4. Concurrency Setup
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, netw := range DefaultNetworks {
		wg.Add(1)

		// Launch a goroutine for each platform
		go func(n Network) {
			defer wg.Done()

			url := n.URL(handle)

			// Create a new browser tab for this iteration
			page, err := bCtx.NewPage()
			if err != nil {
				return
			}
			page.WaitForTimeout(2000)

			// popup
			btn := page.Locator(`svg[aria-label="Close"], button:has-text("Not Now")`)
			if count, _ := btn.Count(); count > 0 {
				btn.First().Click()
			}
			page.Evaluate(`
	document.body.style.overflow = 'auto';
	const modal = document.querySelector('div[role="dialog"]');
	if (modal) modal.remove();
`)

			page.SetExtraHTTPHeaders(map[string]string{
				"accept-language": "en-US,en;q=0.9",
			})
			defer page.Close()

			// Route to the appropriate scraper
			found, profileInfo, followers, lastActive, posts, warn := RouteScraper(ctx, client, page, n.Name, url, handle)

			// Lock the mutex before writing to shared slices
			mu.Lock()
			defer mu.Unlock()

			if warn != "" {
				r.Warnings = append(r.Warnings, warn)
			}

			if found {
				activePlatforms = append(activePlatforms, n.Name)
				allPosts = append(allPosts, posts...)
			}

			results = append(results, core.NetworkResult{
				Name:        n.Name,
				URL:         url,
				Found:       found,
				ProfileInfo: profileInfo,
				Followers:   followers,
				LastActive:  lastActive,
				RecentPosts: posts,
			})
		}(netw)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	r.Username.Networks = results
	r.Username.RecentActivity = formatRecentActivity(activePlatforms)

	if len(allPosts) > 0 {
		newest := findNewestPost(allPosts)
		r.Username.LastPost = newest.Content
		r.Username.LastPostDate = newest.Date
		r.Username.LastPostPlatform = newest.Platform
	} else {
		r.Username.LastPost = "No recent public activity found"
	}

	r.Sources = append(r.Sources, "Hybrid API & Playwright Scraper (Concurrent)")
	return r, nil
}

func formatRecentActivity(platforms []string) string {
	if len(platforms) == 0 {
		return "No recent activity detected"
	}
	return "Active on: " + strings.Join(platforms, ", ")
}

func findNewestPost(posts []core.Post) core.Post {
	newest := posts[0]
	for _, p := range posts {
		if p.Date > newest.Date {
			newest = p
		}
	}
	return newest
}
