package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"osint/internal/core"
)

func NextResultFilename(dir string) (string, error) {
	if err := ensureDirExists(dir); err != nil {
		return "", err
	}

	base := filepath.Join(dir, "result.txt")
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return base, nil
	}

	for i := 2; i < 10000; i++ {
		name := filepath.Join(dir, fmt.Sprintf("result%d.txt", i))
		if _, err := os.Stat(name); os.IsNotExist(err) {
			return name, nil
		}
	}
	return "", fmt.Errorf("too many result files in %s", dir)
}

func ensureDirExists(dir string) error {
	if dir == "." {
		return nil
	}
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return os.MkdirAll(dir, 0o755)
	}
	return err
}

// WriteResult writes results to file (filename can be custom via -o or auto-generated)
func WriteResult(filename string, r core.Result) error {
	body := formatForFile(r)
	return os.WriteFile(filename, []byte(body), 0o644)
}

func formatForFile(r core.Result) string {
	var b strings.Builder

	// OSINT-Master compatible output format
	switch r.Kind {
	case core.KindDomain:
		b.WriteString(fmt.Sprintf("Main Domain: %s\n\n", r.Input))
		b.WriteString(fmt.Sprintf("Subdomains found: %d\n", len(r.Domain.Subdomains)))
		for _, sub := range r.Domain.Subdomains {
			b.WriteString(fmt.Sprintf("  - %s (IP: %s)\n", sub.Name, sub.IP))
			if sub.SSLValid {
				b.WriteString(fmt.Sprintf("    SSL Certificate: Valid until %s\n", sub.SSLExpiry))
			} else {
				b.WriteString(fmt.Sprintf("    SSL Certificate: Not found\n"))
			}
		}

		// List takeover risks separately - collect SubdomainInfo structs, not strings
		var riskySubs []core.SubdomainInfo
		for _, sub := range r.Domain.Subdomains {
			if sub.TakeoverRisk != "" && sub.TakeoverRisk != "none" {
				riskySubs = append(riskySubs, sub)
			}
		}
		if len(riskySubs) > 0 {
			b.WriteString("\nPotential Subdomain Takeover Risks:\n")
			for _, sub := range riskySubs {
				b.WriteString(fmt.Sprintf("  - Subdomain: %s\n", sub.Name))
				b.WriteString(fmt.Sprintf("    %s\n", sub.TakeoverRisk))
				b.WriteString("    Recommended Action: Remove or update the DNS record to prevent potential misuse\n")
			}
		}

	case core.KindIP:
	// Match required output format exactly
	if r.IP.ISP != "" {
		b.WriteString(fmt.Sprintf("ISP: %s\n", r.IP.ISP))
	}
	if r.IP.City != "" {
		b.WriteString(fmt.Sprintf("City: %s\n", r.IP.City))
	}
	if r.IP.Country != "" {
		b.WriteString(fmt.Sprintf("Country: %s\n", r.IP.Country))
	}
	if r.IP.ASN != "" {
		b.WriteString(fmt.Sprintf("ASN: %s\n", r.IP.ASN))
	}
	if r.IP.Lat != 0 || r.IP.Lon != 0 {
		b.WriteString(fmt.Sprintf("Lat/Lon: %.4f / %.4f\n", r.IP.Lat, r.IP.Lon))
	}
	// Abuse data
	if r.IP.KnownIssues != "" {
		b.WriteString(fmt.Sprintf("Known Issues: %s\n", r.IP.KnownIssues))
	} else {
		b.WriteString("Known Issues: No reported abuse\n")
	}

	case core.KindUsername:
		for _, n := range r.Username.Networks {
			val := "Not Found"
			if n.Found {
				val = "Found"
			}
			// Use Title case for network names (Facebook, Twitter, etc.)
			name := n.Name
			if len(name) > 0 {
				name = strings.ToUpper(name[:1]) + name[1:]
			}
			b.WriteString(fmt.Sprintf("%s: %s\n", name, val))
		}

	case core.KindFullName:
		b.WriteString(fmt.Sprintf("First name: %s\n", r.FullName.FirstName))
		b.WriteString(fmt.Sprintf("Last name: %s\n", r.FullName.LastName))
		if r.FullName.Address != "" {
			b.WriteString(fmt.Sprintf("Address: %s\n", r.FullName.Address))
		}
		if r.FullName.Phone != "" {
			b.WriteString(fmt.Sprintf("Number: %s\n", r.FullName.Phone))
		}
	}

	b.WriteString(fmt.Sprintf("\nData saved in result file\n"))
	b.WriteString(fmt.Sprintf("Timestamp: %s\n", r.Timestamp.Format(time.RFC3339)))
	return b.String()
}