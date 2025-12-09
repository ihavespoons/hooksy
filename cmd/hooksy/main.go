package main

import (
	"os"

	"github.com/ihavespoons/hooksy/internal/cli"
)

// Set via ldflags at build time
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.Version = version
	cli.Commit = commit
	cli.Date = date

	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
