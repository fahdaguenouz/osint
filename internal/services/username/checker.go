package username

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// checkProfileDetailed checks profile and extracts metadata
func checkProfileDetailed(ctx context.Context, client *http.Client, networkName, url, handle string) (found bool, profileInfo, followers, lastActive, warning string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "", "", "", networkName + ": request build failed"
	}

	// Rotate user agents to avoid blocks
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
	req.Header.Set("User-Agent", userAgents[0])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return false, "", "", "", networkName + ": request failed"
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	loc := strings.ToLower(resp.Header.Get("Location"))

	// Handle blocks/rate limits
	if code == 401 || code == 403 || code == 429 || code == 999 {
		return false, "", "", "", networkName + ": blocked/rate limited (cannot confirm)"
	}

	// Handle redirects
	if code == 301 || code == 302 || code == 303 || code == 307 || code == 308 {
		if strings.Contains(loc, "login") || strings.Contains(loc, "signin") || strings.Contains(loc, "auth") {
			return false, "", "", "", networkName + ": redirected to login (cannot confirm)"
		}
		if networkName == "github" && strings.Contains(loc, "github.com/"+strings.ToLower(handle)) {
			// GitHub canonical redirect - profile exists
			return true, "GitHub profile", "", "", ""
		}
		return false, "", "", "", networkName + ": redirected (cannot confirm)"
	}

	// Not found
	if code == 404 || code == 410 {
		return false, "", "", "", ""
	}

	// Parse HTML for profile info
	if code == 200 {
		snippet, _ := readSnippet(resp.Body, 128*1024) // 128KB
		html := strings.ToLower(snippet)
		text := snippet // Keep original case for extraction

		switch networkName {
		case "github":
			return parseGitHub(text, html, handle)
		case "instagram":
			return parseInstagram(text, html)
		case "twitter":
			return parseTwitter(text, html)
		case "facebook":
			return parseFacebook(text, html)
		case "tiktok":
			return parseTikTok(text, html)
		default:
			return true, "Profile found", "", "", ""
		}
	}

	return false, "", "", "", networkName + ": unexpected HTTP status (cannot confirm)"
}

// GitHub parser
func parseGitHub(text, html, handle string) (bool, string, string, string, string) {
	// Check for 404 page
	if strings.Contains(html, "page not found") || strings.Contains(html, "404") && strings.Contains(html, "not found") {
		return false, "", "", "", ""
	}

	// Extract bio - look for common patterns
	bio := extractBetween(text, `"bio":`, `,`, 100)
	if bio == "" {
		bio = extractBetween(text, `<div class="p-note user-profile-bio mb-3 js-user-profile-bio f4">`, `</div>`, 200)
	}
	
	// Extract followers
	followers := extractBetween(text, `"followers":`, `,`, 20)
	if followers == "" {
		followers = extractBetween(text, `<span class="text-bold color-fg-default">`, `</span>`, 20)
	}

	// Clean up
	bio = cleanJSONString(bio)
	followers = cleanJSONString(followers)

	return true, bio, followers, "", ""
}

// Instagram parser
func parseInstagram(text, html string) (bool, string, string, string, string) {
	// Not found markers
	if strings.Contains(html, "page not found") || 
	   strings.Contains(html, "sorry, this page isn't available") ||
	   strings.Contains(html, "the link you followed may be broken") {
		return false, "", "", "", ""
	}

	// Login wall
	if strings.Contains(html, "log in") && strings.Contains(html, "sign up") {
		return false, "", "", "", "instagram: login wall (cannot confirm)"
	}

	// Extract bio from meta description or sharedData
	bio := extractBetween(text, `"biography":`, `,`, 150)
	if bio == "" {
		bio = extractBetween(text, `<meta property="og:description" content="`, `"`, 200)
	}

	// Extract followers count
	followers := extractBetween(text, `"edge_followed_by":{"count":`, `}`, 20)
	if followers == "" {
		followers = extractBetween(text, `"followers_count":`, `,`, 20)
	}

	bio = cleanJSONString(bio)
	followers = cleanJSONString(followers)

	return true, bio, followers, "", ""
}

// Twitter/X parser
func parseTwitter(text, html string) (bool, string, string, string, string) {
	// Account doesn't exist
	if strings.Contains(html, "this account doesn’t exist") ||
	   strings.Contains(html, "this account doesn't exist") ||
	   strings.Contains(html, "account suspended") {
		return false, "", "", "", ""
	}

	// Login wall
	if strings.Contains(html, "sign in to x") || strings.Contains(html, "log in") && strings.Contains(html, "x.com") {
		return false, "", "", "", "twitter: login wall (cannot confirm)"
	}

	// Extract bio
	bio := extractBetween(text, `<meta property="og:description" content="`, `"`, 200)
	if bio == "" {
		bio = extractBetween(text, `"description":`, `,`, 200)
	}

	// Extract followers
	followers := extractBetween(text, `"followers_count":`, `,`, 20)
	if followers == "" {
		followers = extractBetween(text, `"followers":`, `,`, 20)
	}

	bio = cleanJSONString(bio)
	followers = cleanJSONString(followers)

	return true, bio, followers, "", ""
}

// Facebook parser
func parseFacebook(text, html string) (bool, string, string, string, string) {
	// Not available markers
	if strings.Contains(html, "this page isn't available") ||
	   strings.Contains(html, "page may have been removed") ||
	   strings.Contains(html, "content isn't available") {
		return false, "", "", "", ""
	}

	// Login wall
	if strings.Contains(html, "log into facebook") || strings.Contains(html, "log in to continue") {
		return false, "", "", "", "facebook: login wall (cannot confirm)"
	}

	// Extract basic info - Facebook is heavily restricted
	bio := extractBetween(text, `<meta name="description" content="`, `"`, 200)
	
	return true, bio, "", "", ""
}

// TikTok parser
func parseTikTok(text, html string) (bool, string, string, string, string) {
	// Not found
	if strings.Contains(html, "couldn't find this account") ||
	   strings.Contains(html, "couldn&#39;t find this account") {
		return false, "", "", "", ""
	}

	// Captcha/verification wall
	if strings.Contains(html, "/captcha") ||
	   strings.Contains(html, "verify to continue") ||
	   strings.Contains(html, "security verification") {
		return false, "", "", "", "tiktok: verification wall (cannot confirm)"
	}

	// Extract bio
	bio := extractBetween(text, `"signature":`, `,`, 150)
	if bio == "" {
		bio = extractBetween(text, `<h2 class="share-desc">`, `</h2>`, 150)
	}

	// Extract followers
	followers := extractBetween(text, `"followerCount":`, `,`, 20)
	if followers == "" {
		followers = extractBetween(text, `"fans":`, `,`, 20)
	}

	bio = cleanJSONString(bio)
	followers = cleanJSONString(followers)

	return true, bio, followers, "", ""
}

// Helper functions
func extractBetween(text, start, end string, maxLen int) string {
	startIdx := strings.Index(text, start)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(start)
	
	endIdx := strings.Index(text[startIdx:], end)
	if endIdx == -1 || endIdx > maxLen {
		endIdx = maxLen
		if endIdx > len(text[startIdx:]) {
			endIdx = len(text[startIdx:])
		}
	}
	
	result := text[startIdx : startIdx+endIdx]
	return strings.TrimSpace(result)
}

func cleanJSONString(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	s = strings.ReplaceAll(s, `\n`, " ")
	s = strings.ReplaceAll(s, `\u0026`, "&")
	s = strings.ReplaceAll(s, `\\`, `\`)
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return s
}

func readSnippet(r io.Reader, max int64) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, max))
	if err != nil {
		return "", err
	}
	return string(b), nil
}