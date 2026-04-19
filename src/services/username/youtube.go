package username

import (
	"osint/src/core"
	"regexp"
	"strings"

	"github.com/playwright-community/playwright-go"
)

// --- YOUTUBE (Easier Alternative to LinkedIn) ---
func scrapeYouTubePlaywright(page playwright.Page, url string) (bool, string, string, string, []core.Post, string) {

	page.AddInitScript(playwright.Script{
		Content: playwright.String(`
			Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
			delete window.__playwright;
			window.chrome = { runtime: {} };
		`),
	})

	_, err := page.Goto(url, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(15000),
	})
	if err != nil {
		return false, "", "", "", nil, "youtube: navigation failed"
	}

	page.WaitForTimeout(3000)

	// Check for not found
	title, _ := page.Title()
	if strings.Contains(title, "Not Found") || strings.Contains(title, "404") {
		return false, "", "", "", nil, ""
	}

	// Extract from meta tags (YouTube is very scraper-friendly)
	var displayName, bioText, subscribers string

	// Try meta title
	metaTitle, _ := page.Locator(`meta[property="og:title"]`).GetAttribute("content")
	if metaTitle != "" {
		displayName = strings.TrimSpace(metaTitle)
	}

	// Try meta description for bio
	metaDesc, _ := page.Locator(`meta[property="og:description"]`).GetAttribute("content")
	if metaDesc != "" {
		bioText = strings.TrimSpace(metaDesc)
	}

	// Extract subscriber count from page content
	pageText, _ := page.Locator(`body`).InnerText()
	if pageText != "" {
		// Look for subscriber patterns: "1.2M subscribers" or "1,234 subscribers"
		subRegex := regexp.MustCompile(`(?i)([\d,.]+[KMBkmb]?)\s+subscribers?`)
		if match := subRegex.FindStringSubmatch(pageText); len(match) >= 2 {
			subscribers = match[1]
		}
	}

	// Fallback to title parsing
	if displayName == "" {
		if idx := strings.Index(title, " - YouTube"); idx != -1 {
			displayName = strings.TrimSpace(title[:idx])
		}
	}

	if displayName == "" {
		return false, "", "", "", nil, "youtube: unable to extract profile data"
	}

	profileInfo := displayName
	if bioText != "" {
		if len(bioText) > 200 {
			bioText = bioText[:200] + "..."
		}
		profileInfo += " | " + bioText
	}

	return true, profileInfo, subscribers, "", nil, ""
}
