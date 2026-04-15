package username

import (
	"context"
	"net/http"

	"github.com/playwright-community/playwright-go"
	"osint/internal/core"
)

// RouteScraper decides whether to use HTTP or Playwright based on the platform
func RouteScraper(ctx context.Context, client *http.Client, page playwright.Page, networkName, url, handle string) (bool, string, string, string, []core.Post, string) {
	switch networkName {

	// Open API platforms - use fast HTTP functions
	case "github":
		return fetchGitHubWithRepos(ctx, client, handle) // Assuming this exists in your codebase
	case "reddit":
		return checkRedditJSON(ctx, client, handle)
	case "tiktok":
		return scrapeTikTokPlaywright(page, url, handle)
	case "medium":
		return scrapeMediumPlaywright(page, url, handle)
	case "youtube":
		return scrapeYouTubePlaywright(page, url, handle)

	// JS-heavy platforms - use the Playwright page
	case "instagram":
		return scrapeInstagramPlaywright(page, url, handle)

	default:
		return false, "", "", "", nil, networkName + ": unsupported network"
	}
}
