// Package main provides the meltify-polyseed CLI executable.
package main

import (
	"fmt"
	"os"

	"github.com/ZenTenApp/meltify/internal/app/polyseed"
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
	if err := polyseed.ExecutePolyseed(os.Args[1:], os.Stdin, info); err != nil {
		fmt.Fprintln(os.Stderr, "meltify-polyseed: "+err.Error())
		os.Exit(1)
	}
}
