#!/usr/bin/env bash

export GO111MODULE=on

set -e
echo "" > coverage.txt

./mockgen.sh

for d in $(go list ./... | grep -v mock); do
    go test -race -tags test -coverprofile=profile.out -covermode=atomic $d
    if [ -f profile.out ]; then
        cat profile.out >> coverage.txt
        rm profile.out
    fi
done
