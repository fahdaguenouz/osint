package username

import (
	"context"
	"io"
	"net/http"
	"osint/internal/core"
	"strings"
)

func checkRedditJSON(ctx context.Context, client *http.Client, handle string) (bool, string, string, string, []core.Post, string) {
	handle = strings.ToLower(handle)
	url := "https://www.reddit.com/user/" + handle + "/about.json"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return false, "", "", "", nil, "reddit: request failed"
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return false, "", "", "", nil, ""
	}

	body, _ := io.ReadAll(resp.Body)
	data := string(body)

	// Not found check
	// ❌ Deleted / Not Found
	if strings.Contains(data, `"error": 404`) ||
		strings.Contains(data, `"message": "Not Found"`) ||
		!strings.Contains(data, `"kind": "t2"`) {
		return false, "", "", "", nil, ""
	}

	// Extract fields manually (keep your style)
	name := extractBetween(data, `"name":"`, `"`, 100)
	if name == "" {
		return false, "", "", "", nil, ""
	}
	bio := extractBetween(data, `"public_description":"`, `"`, 200)
	karma := extractBetween(data, `"total_karma":`, ",", 20)

	info := ""

	if name != "" {
		info += "Author: " + cleanJSONString(name)
	}

	if bio != "" {
		info += " | Bio: " + cleanJSONString(bio)
	}

	if karma != "" {
		info += " | Karma: " + karma
	}

	return true, info, "", "", nil, ""
}
