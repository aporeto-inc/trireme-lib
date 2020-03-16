#!/usr/bin/env bash

export GO111MODULE=auto
export CGO_ENABLED=0
export GOOS=windows
export GOARCH=amd64

# goimports and gofmt complain about cr-lf line endings, so don't run them on
#	a Windows machine where git is configured to auto-convert line endings

OS="$(uname -s)"
if [[ "$OS" == *"NT-"* ]]; then
	GOIMPORTS_OPTION=
	GOFMT_OPTION=
else
	GOIMPORTS_OPTION="--enable=goimports"
	GOFMT_OPTION="--enable=gofmt"
fi

golangci-lint run \
    --verbose \
    --skip-dirs='[third_party|test|vendor]' \
    --skip-files='[.*\.pb\.go|.*\.gen\.go]' \
    --deadline=20m \
    --disable-all \
    --exclude-use-default=false \
    --enable=errcheck \
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
    --enable=typecheck \
    $GOIMPORTS_OPTION \
    $GOFMT_OPTION \
    ./...
