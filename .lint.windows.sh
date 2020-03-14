#!/usr/bin/env bash

# goimports and gofmt complain about cr-lf line endings, so don't run them on 
#	a Windows machine where git is configured to auto-convert line endings

OS=`uname -s`
if [[ $OS == *"NT-"* ]]; then 
	GOIMPORTS_OPTION=
	GOFMT_OPTION=
else
	GOIMPORTS_OPTION=--enable=goimports
	GOFMT_OPTION=--enable=gofmt
fi
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 golangci-lint run --deadline=10m --disable-all --exclude-use-default=false --enable=errcheck --enable=ineffassign --enable=govet --enable=golint --enable=unused --enable=structcheck --enable=varcheck --enable=deadcode --enable=unconvert --enable=goconst --enable=gosimple --enable=misspell --enable=staticcheck --enable=unparam --enable=prealloc --enable=nakedret --enable=typecheck $GOIMPORTS_OPTION $GOFMT_OPTION --skip-dirs=vendor/github.com/iovisor ./...
