package main

import (
	"fmt"
	"os"

	"osint/internal/cli"
	"osint/internal/core"
	"osint/internal/output"
	"osint/internal/services/domain"
	"osint/internal/services/ip"
	"osint/internal/services/username"
)

func main() {
	opts, showHelp, err := cli.ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		cli.PrintHelp(os.Stderr)
		os.Exit(2)
	}
	if showHelp {
		cli.PrintHelp(os.Stdout)
		return
	}

	var (
		res    core.Result
		runErr error
	)

	switch opts.Mode {
	case cli.ModeIP:
		res, runErr = ip.Run(opts.Query)
	case cli.ModeUsername:
		res, runErr = username.Run(opts.Query)
	case cli.ModeDomain:
		res, runErr = domain.Run(opts.Query) // NOW ENABLED
	default:
		fmt.Fprintln(os.Stderr, "Error: no mode selected (-n, -i, -u, -d)")
		cli.PrintHelp(os.Stderr)
		os.Exit(2)
	}

	// Always print results (so errors show up in terminal)
	cli.PrintResult(os.Stdout, res)

	// If there was an error during execution, don't write to file
	if runErr != nil {
		os.Exit(1)
	}

	// Determine output filename: use -o if provided, otherwise auto-generate
	filename := opts.Output
	if filename == "" {
		filename, err = output.NextResultFilename(".")
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
	}

	if err := output.WriteResult(filename, res); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	fmt.Printf("Data saved in %s\n", filename)
}