package cli

import (
	"fmt"
	"io"
	"strings"

	"osint/src/core"
)

func PrintResult(w io.Writer, r core.Result) {
	if r.Error != "" {
		fmt.Fprintf(w, "Error: %s\n", r.Error)
		return
	}

	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "Warning: %s\n", warn)
	}

	switch r.Kind {

	case core.KindIP:
		if r.IP.ISP != "" {
			fmt.Fprintf(w, "ISP: %s\n", r.IP.ISP)
		}
		if r.IP.City != "" {
			fmt.Fprintf(w, "City: %s\n", r.IP.City)
		}
		if r.IP.Country != "" {
			fmt.Fprintf(w, "Country: %s\n", r.IP.Country)
		}
		if r.IP.ASN != "" {
			fmt.Fprintf(w, "ASN: %s\n", r.IP.ASN)
		}
		if r.IP.Lat != 0 || r.IP.Lon != 0 {
			fmt.Fprintf(w, "Lat/Lon: %.4f, %.4f\n", r.IP.Lat, r.IP.Lon)
		}
		// Abuse data
		if r.IP.KnownIssues != "" {
			fmt.Fprintf(w, "Known Issues: %s\n", r.IP.KnownIssues)
		} else {
			fmt.Fprintf(w, "Known Issues: No reported abuse\n")
		}

	case core.KindUsername:
		for _, n := range r.Username.Networks {
			val := "Not Found"
			if n.Found {
				val = "Found"
			}

			name := n.Name
			if len(name) > 0 {
				name = strings.ToUpper(name[:1]) + name[1:]
			}

			fmt.Fprintf(w, "%s: %s", name, val)
			if n.Followers != "" {
				fmt.Fprintf(w, " (%s followers)", n.Followers)
			}
			fmt.Fprintln(w)

			if n.ProfileInfo != "" {
				if n.Name == "tiktok" {
					fmt.Fprintf(w, "  Author: %s\n", n.ProfileInfo)
				} else {
					fmt.Fprintf(w, "  Bio: %s\n", n.ProfileInfo)
				}
			}
		}

		fmt.Fprintf(w, "\nRecent Activity: %s\n", r.Username.RecentActivity)

		if r.Username.LastPostPlatform != "" {
			fmt.Fprintf(w, "Last Post: %s on %s (%s)\n",
				r.Username.LastPost,
				r.Username.LastPostPlatform,
				r.Username.LastPostDate)
		}

	case core.KindDomain: 
		fmt.Fprintf(w, "Main Domain: %s\n", r.Input)
		fmt.Fprintf(w, "\nSubdomains found: %d\n", len(r.Domain.Subdomains))

		for _, sub := range r.Domain.Subdomains {
			ip := sub.IP
			if ip == "" {
				ip = "unresolved"
			}
			fmt.Fprintf(w, "  - %s (IP: %s)\n", sub.Name, ip)

			if sub.SSLValid {
				fmt.Fprintf(w, "    SSL Certificate: Valid until %s\n", sub.SSLExpiry)
			}
		}

		// Show takeover risks
		riskCount := 0
		for _, sub := range r.Domain.Subdomains {
			if sub.TakeoverRisk != "" && sub.TakeoverRisk != "none" {
				if riskCount == 0 {
					fmt.Fprintf(w, "\nPotential Subdomain Takeover Risks:\n")
				}
				fmt.Fprintf(w, "  - %s: %s\n", sub.Name, sub.TakeoverRisk)
				riskCount++
			}
		}
		if riskCount == 0 {
			fmt.Fprintf(w, "\nPotential Subdomain Takeover Risks: None detected\n")
		}

	default:
		fmt.Fprintln(w, "No result.")
	}
}
