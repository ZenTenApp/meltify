// Package main provides the meltify-dnssec CLI executable.
package main

import (
	"fmt"
	"os"

	"github.com/ZenTenApp/meltify/internal/app/dnssec"
	"github.com/ZenTenApp/meltify/internal/cliutil"
)

// Populated at build time via -ldflags (set by GoReleaser).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	info := cliutil.VersionInfo{Version: version, Commit: commit, Date: date}
	if err := dnssec.Execute(os.Args[1:], os.Stdin, info); err != nil {
		fmt.Fprintln(os.Stderr, "meltify-dnssec: "+err.Error())
		os.Exit(1)
	}
}
