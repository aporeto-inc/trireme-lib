#!/bin/sh

#
# linter has trouble with go modules cache.
# so we run it in a local vendor dir mode, but we don't
# lint the vendor files.  Just need to load them so the linter can find them
#
GO111MODULE=auto go mod vendor
GO111MODULE=auto golangci-lint run \
    --verbose \
    --modules-download-mode=vendor \
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

