#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> go test ./..."
go test ./...

echo "==> go build ./..."
go build ./...

echo "==> hard lint"
golangci-lint run --config .golangci.yml ./...

echo "==> soft lint"
golangci-lint run --config .golangci-soft.yml ./...

echo "==> all checks passed"
