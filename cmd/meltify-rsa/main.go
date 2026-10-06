// Package main provides the meltify-rsa CLI executable.
package main

import (
	"fmt"
	"os"

	meltrsa "github.com/ZenTenApp/meltify/internal/app/rsa"
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
	if err := meltrsa.Execute(os.Args[1:], os.Stdin, info); err != nil {
		fmt.Fprintln(os.Stderr, "meltify-rsa: "+err.Error())
		os.Exit(1)
	}
}
