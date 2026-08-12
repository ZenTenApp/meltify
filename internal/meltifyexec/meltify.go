// Package meltifyexec runs the meltify executable as a key-material provider.
package meltifyexec

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const seedSize = 32

// ExtractSeed runs the meltify executable and returns its raw 32-byte Ed25519 seed output.
func ExtractSeed(keyPath, subaccount string, stdin io.Reader) ([]byte, error) {
	meltifyPath, err := findMeltifyExecutable()
	if err != nil {
		return nil, err
	}

	args := make([]string, 0, 3) //nolint:mnd
	if keyPath != "" && keyPath != "-" {
		args = append(args, keyPath)
	}
	if subaccount != "" {
		args = append(args, "--subaccount", subaccount)
	}

	cmd := exec.CommandContext(context.Background(), meltifyPath, args...) //nolint:gosec // Intentional execution of sibling/PATH meltify binary.
	cmd.Stdin = stdin
	cmd.Stderr = os.Stderr

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("meltify failed: %w", err)
	}

	seedHex := strings.TrimSpace(stdout.String())
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("meltify produced invalid seed hex: %w", err)
	}
	if len(seed) != seedSize {
		return nil, fmt.Errorf("meltify produced %d seed bytes, expected %d", len(seed), seedSize)
	}
	return seed, nil
}

func findMeltifyExecutable() (string, error) {
	self, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(self), "meltify")
		if isExecutable(candidate) {
			return candidate, nil
		}
	}

	path, err := exec.LookPath("meltify")
	if err == nil {
		return path, nil
	}

	return "", errors.New("meltify executable not found next to this executable or in PATH")
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}
