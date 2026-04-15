package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

type Mode int

const (
	ModeNone     Mode = iota
	ModeIP            // -i
	ModeUsername      // -u
	ModeDomain        // -d (NEW)
)

type Options struct {
	Mode   Mode
	Query  string
	Output string // -o flag
}

func ParseArgs(args []string) (Options, bool, error) {
	fs := flag.NewFlagSet("osintmaster", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we print our own help

	var (
		i    string
		u    string
		d    string // NEW: domain
		o    string // NEW: output file
		help bool
	)

	// OSINT-Master compatible flags
	fs.StringVar(&i, "i", "", "Search information by IP address")
	fs.StringVar(&u, "u", "", "Search information by username")
	fs.StringVar(&d, "d", "", "Enumerate subdomains and check for takeover risks")
	fs.StringVar(&o, "o", "", "File name to save output")

	// Support both -h and --help
	fs.BoolVar(&help, "h", false, "Show help")
	fs.BoolVar(&help, "help", false, "Show help")

	if err := fs.Parse(args); err != nil {
		return Options{}, false, err
	}
	if help {
		return Options{}, true, nil
	}

	rest := fs.Args()

	selected := 0
	mode := ModeNone
	query := ""

	joinValueAndRest := func(val string) string {
		parts := []string{}
		if strings.TrimSpace(val) != "" {
			parts = append(parts, val)
		}
		if len(rest) > 0 {
			parts = append(parts, rest...)
		}
		return strings.TrimSpace(strings.Join(parts, " "))
	}

	// Check which flags were actually provided in raw args
	// This is more reliable than checking if value != "" because
	// empty values could be valid in some cases
	iProvided := hasAny(args, "-i")
	uProvided := hasAny(args, "-u")
	dProvided := hasAny(args, "-d")

	if iProvided {
		selected++
		mode = ModeIP
		query = joinValueAndRest(i)
	}
	if uProvided {
		selected++
		mode = ModeUsername
		query = joinValueAndRest(u)
	}
	if dProvided {
		selected++
		mode = ModeDomain
		query = joinValueAndRest(d)
	}

	if selected == 0 {
		return Options{}, true, nil // Show help
	}
	if selected > 1 {
		return Options{}, false, errors.New("choose only one option: -n, -i, -u, or -d")
	}
	if strings.TrimSpace(query) == "" {
		return Options{}, false, fmt.Errorf("missing value for selected option")
	}

	return Options{
		Mode:   mode,
		Query:  query,
		Output: o,
	}, false, nil
}

// PrintHelp displays the OSINT-Master compatible help menu
func PrintHelp(w io.Writer) {
	fmt.Fprintln(w, "Welcome to osintmaster multi-function Tool")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "OPTIONS:")
	fmt.Fprintln(w, "    -i  \"IP Address\"       Search information by IP address")
	fmt.Fprintln(w, "    -u  \"Username\"         Search information by username")
	fmt.Fprintln(w, "    -d  \"Domain\"           Enumerate subdomains and check for takeover risks")
	fmt.Fprintln(w, "    -o  \"FileName\"         File name to save output")
	fmt.Fprintln(w, "    --help                 Display this help message")
}

// hasAny checks if any of the provided flag names exist in args
// This detects if a flag was explicitly passed, even if its value is empty
func hasAny(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			// Check exact match or prefix with = for -flag=value syntax
			if a == n || strings.HasPrefix(a, n+"=") {
				return true
			}
		}
	}
	return false
}
