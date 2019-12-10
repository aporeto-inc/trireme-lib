#!/bin/sh

golangci-lint run \
    --deadline=10m \
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

