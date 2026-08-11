// Package main provides the meltify-info CLI executable.
package main

import (
	"fmt"
	"os"

	"github.com/ZenTenApp/meltify/internal/app/info"
	"github.com/ZenTenApp/meltify/internal/cliutil"
)

// Populated at build time via -ldflags (set by GoReleaser).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	vinfo := cliutil.VersionInfo{Version: version, Commit: commit, Date: date}
	if err := info.ExecuteInfo(os.Args[1:], os.Stdin, vinfo); err != nil {
		fmt.Fprintln(os.Stderr, "meltify-info: "+err.Error())
		os.Exit(1)
	}
}