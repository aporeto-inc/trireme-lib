#!/usr/bin/env bash

set -e
echo "" > coverage.windows.txt

for d in $(go list ./... | grep -v remoteenforcer | grep -v remoteapi); do
    GOOS=windows GOARCH=amd64 go test -tags test -exec wine -coverprofile=profile.windows.out -covermode=atomic $d
    if [ -f profile.windows.out ]; then
        cat profile.windows.out >> coverage.windows.txt
        rm profile.windows.out
    fi
done
