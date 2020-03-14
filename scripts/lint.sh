#!/bin/sh

GO111MODULE=auto golangci-lint run \
    --verbose \
    --skip-dirs='[third_party|test|vendor]' \
    --skip-files='[.*\.pb\.go|.*\.gen\.go]' \
    --deadline=20m \
    --disable-all \
    --exclude-use-default=false \
    --enable=errcheck \
    --enable=goimports \
    --enable=ineffassign \
    --enable=govet \
    --enable=golint \
    --enable=unused \
    --enable=structcheck \
    --enable=varcheck \
    --enable=deadcode \
    --enable=unconvert \
    --enable=goconst \
    --enable=gosimple \
    --enable=misspell \
    --enable=staticcheck \
    --enable=unparam \
    --enable=prealloc \
    --enable=nakedret \
    --enable=gofmt \
    --enable=typecheck \
    ./...

