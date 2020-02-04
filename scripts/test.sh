#!/usr/bin/env bash

export GO111MODULE=auto

# set -e
echo >| coverage.txt

echo
echo  "========= BEGIN TESTS ==========="
echo

for d in $(go list ./... | grep -E -v '(mock|bpf)' ); do
    go test -v -race -tags test -coverprofile=profile.out -covermode=atomic "$d"
    if [ -f profile.out ]; then
        cat profile.out >> coverage.txt
        rm profile.out
    fi
done

echo
echo  "========= END TESTS ==========="
echo
