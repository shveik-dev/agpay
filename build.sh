#!/bin/sh
# Test and build in rootless podman, offline, RAM only. Output: ./dist/agpay (static linux/amd64).
set -eu
cd "$(dirname "$0")"
MOD=${GOMODCACHE_HOST:-$HOME/go/pkg/mod}
run() { podman run --rm --network=none --read-only --tmpfs /tmp:exec,size=2g -e GOFLAGS=-mod=mod -e GOPROXY=off -e CGO_ENABLED=0 \
  -e GOCACHE=/tmp/gc -e GOMODCACHE=/mod -v "$MOD":/mod:ro -v "$PWD":/src:ro "$@"; }
run -w /src golang:1.25 go vet ./...
run -w /src golang:1.25 go test ./... -count=1
mkdir -p dist
podman run --rm --network=none --tmpfs /tmp:exec,size=2g -e GOFLAGS=-mod=mod -e GOPROXY=off -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
  -e GOCACHE=/tmp/gc -e GOMODCACHE=/mod -v "$MOD":/mod:ro -v "$PWD":/src:ro -v "$PWD/dist":/out -w /src golang:1.25 \
  go build -trimpath -ldflags="-s -w -X github.com/shveik-dev/agpay/internal/app.Version=${VERSION:-dev}" -o /out/agpay ./cmd/agpay
sha256sum dist/agpay
