// Package main provides the meltify-dkim CLI executable.
package main

import (
	"fmt"
	"os"

	"github.com/ZenTenApp/meltify/internal/app/dkim"
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
	if err := dkim.Execute(os.Args[1:], os.Stdin, info); err != nil {
		fmt.Fprintln(os.Stderr, "meltify-dkim: "+err.Error())
		os.Exit(1)
	}
}
