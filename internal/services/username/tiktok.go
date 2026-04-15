package username

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"osint/internal/core"
	"regexp"
	"strings"
	"time"

	"github.com/playwright-community/playwright-go"
)

// --- TIKTOK (Enhanced with Multiple Techniques) ---
func scrapeTikTokPlaywright(page playwright.Page, url, handle string) (bool, string, string, string, []core.Post, string) {

	// TECHNIQUE 1: Try mobile user-agent (less restrictive)
	mobileUserAgent := "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"

	page.SetExtraHTTPHeaders(map[string]string{
		"Accept-Language": "en-US,en;q=0.9",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"User-Agent":      mobileUserAgent,
		"Referer":         "https://www.tiktok.com/",
	})

	// Enhanced stealth to bypass TikTok's bot detection
	page.AddInitScript(playwright.Script{
		Content: playwright.String(`
			// Override navigator.webdriver
			Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
			delete window.__playwright;
			
			// Fake Chrome runtime
			window.chrome = { runtime: {} };
			
			// Override permissions
			const originalQuery = window.navigator.permissions.query;
			window.navigator.permissions.query = (parameters) => (
				parameters.name === 'notifications' ?
					Promise.resolve({ state: Notification.permission }) :
					originalQuery(parameters)
			);
			
			// Add fake plugins
			Object.defineProperty(navigator, 'plugins', {
				get: () => [1, 2, 3, 4, 5]
			});
			
			// Override languages
			Object.defineProperty(navigator, 'languages', {
				get: () => ['en-US', 'en']
			});
			
			// Fake screen dimensions
			Object.defineProperty(screen, 'width', { get: () => 375 });
			Object.defineProperty(screen, 'height', { get: () => 812 });
		`),
	})

	// Navigate with longer timeout for TikTok's heavy JS
	_, err := page.Goto(url, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(25000),
	})
	if err != nil {
		// Try fallback API method
		return scrapeTikTokAPI(handle)
	}

	// Long wait for TikTok's dynamic content
	page.WaitForTimeout(5000)

	// Handle common TikTok popups
	popupSelectors := []string{
		`button[aria-label="Close"]`,
		`div[class*="close"]`,
		`svg[class*="close"]`,
		`[data-e2e="close"]`,
	}

	for _, sel := range popupSelectors {
		btn := page.Locator(sel)
		if count, _ := btn.Count(); count > 0 {
			btn.First().Click()
			page.WaitForTimeout(500)
		}
	}

	// Check for verification/CAPTCHA
	title, _ := page.Title()
	currentURL := page.URL()

	if strings.Contains(title, "Verify") ||
		strings.Contains(title, "CAPTCHA") ||
		strings.Contains(title, "Robot") ||
		strings.Contains(currentURL, "/captcha/") {
		// Try fallback API method
		return scrapeTikTokAPI(handle)
	}

	// Check for not found
	if strings.Contains(title, "Not Found") ||
		strings.Contains(title, "404") ||
		strings.Contains(title, "Couldn't find this account") {
		return false, "", "", "", nil, ""
	}

	// Extract profile info
	var displayName, bioText, followers, following, likes string

	// Strategy 1: Meta tags
	metaTitle, _ := page.Locator(`meta[property="og:title"]`).GetAttribute("content")
	if metaTitle != "" {
		displayName = strings.TrimSpace(metaTitle)
	}

	metaDesc, _ := page.Locator(`meta[property="og:description"]`).GetAttribute("content")
	if metaDesc != "" {
		bioText = strings.TrimSpace(metaDesc)
	}

	// Strategy 2: Try TikTok specific data attributes
	if displayName == "" {
		nameSelectors := []string{
			`[data-e2e="user-title"]`,
			`[data-e2e="user-subtitle"]`,
			`h1`,
			`h2`,
		}
		for _, sel := range nameSelectors {
			if text, err := page.Locator(sel).First().InnerText(); err == nil && text != "" {
				displayName = strings.TrimSpace(text)
				break
			}
		}
	}

	// Strategy 3: Extract stats from page content
	pageText, _ := page.Locator(`body`).InnerText()
	if pageText != "" {
		// Followers
		followersRegex := regexp.MustCompile(`(?i)([\d,.]+[KMBkmb]?)\s+followers?`)
		if match := followersRegex.FindStringSubmatch(pageText); len(match) >= 2 {
			followers = match[1]
		}

		// Following
		followingRegex := regexp.MustCompile(`(?i)([\d,.]+[KMBkmb]?)\s+following`)
		if match := followingRegex.FindStringSubmatch(pageText); len(match) >= 2 {
			following = match[1]
		}

		// Likes
		likesRegex := regexp.MustCompile(`(?i)([\d,.]+[KMBkmb]?)\s+likes?`)
		if match := likesRegex.FindStringSubmatch(pageText); len(match) >= 2 {
			likes = match[1]
		}
	}

	// Strategy 4: Try to extract from JSON-LD or embedded data
	jsonLD, _ := page.Locator(`script[type="application/ld+json"]`).InnerText()
	if jsonLD != "" {
		// Parse JSON-LD for profile info
		var ldData map[string]interface{}
		if err := json.Unmarshal([]byte(jsonLD), &ldData); err == nil {
			if name, ok := ldData["name"].(string); ok && name != "" {
				displayName = name
			}
			if desc, ok := ldData["description"].(string); ok && desc != "" {
				bioText = desc
			}
		}
	}

	if displayName == "" {
		// Try fallback API method
		return scrapeTikTokAPI(handle)
	}

	// Build profile info
	profileInfo := displayName
	if bioText != "" {
		if len(bioText) > 200 {
			bioText = bioText[:200] + "..."
		}
		profileInfo += " | " + bioText
	}

	// Build followers string with all stats
	var statsParts []string
	if followers != "" {
		statsParts = append(statsParts, followers+" followers")
	}
	if following != "" {
		statsParts = append(statsParts, following+" following")
	}
	if likes != "" {
		statsParts = append(statsParts, likes+" likes")
	}
	followersStr := strings.Join(statsParts, ", ")

	return true, profileInfo, followersStr, "", nil, ""
}

// --- TIKTOK API FALLBACK (Unofficial) ---
func scrapeTikTokAPI(handle string) (bool, string, string, string, []core.Post, string) {
	// Try to use TikTok's oembed API or other public endpoints
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Try oEmbed endpoint
	oembedURL := fmt.Sprintf("https://www.tiktok.com/oembed?url=https://www.tiktok.com/@%s", handle)
	
	req, err := http.NewRequest(http.MethodGet, oembedURL, nil)
	if err != nil {
		return false, "", "", "", nil, "tiktok: api request failed"
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15")
	req.Header.Set("Referer", "https://www.tiktok.com/")

	resp, err := client.Do(req)
	if err != nil {
		return false, "", "", "", nil, "tiktok: api connection error"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, "", "", "", nil, "tiktok: api returned non-200"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", "", "", nil, "tiktok: api read failed"
	}

	var oembedData struct {
		Title       string `json:"title"`
		AuthorName  string `json:"author_name"`
		AuthorURL   string `json:"author_url"`
		ThumbnailURL string `json:"thumbnail_url"`
	}

	if err := json.Unmarshal(body, &oembedData); err != nil {
		return false, "", "", "", nil, "tiktok: api json parse failed"
	}

	if oembedData.AuthorName == "" {
		return false, "", "", "", nil, ""
	}

	profileInfo := oembedData.AuthorName
	if oembedData.Title != "" {
		profileInfo += " | " + oembedData.Title
	}

	return true, profileInfo, "", "", nil, "tiktok: limited data from api"
}