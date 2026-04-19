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
	ModeDomain        // -d
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
		d    string
		o    string
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

	selected := 0
	mode := ModeNone
	query := ""

	// Check which flags were provided with values
	if strings.TrimSpace(i) != "" {
		selected++
		mode = ModeIP
		query = i
	}
	if strings.TrimSpace(u) != "" {
		selected++
		mode = ModeUsername
		query = u
	}
	if strings.TrimSpace(d) != "" {
		selected++
		mode = ModeDomain
		query = d
	}

	if selected == 0 {
		return Options{}, true, nil // Show help if no mode selected
	}
	if selected > 1 {
		return Options{}, false, errors.New("choose only one option: -i, -u, or -d")
	}
	
	return Options{
		Mode:   mode,
		Query:  strings.TrimSpace(query),
		Output: strings.TrimSpace(o),
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