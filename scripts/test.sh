#!/usr/bin/env bash

export GO111MODULE=on

# set -e
echo >| coverage.txt

# temporarily for debugging travis build
# how did this even work all this time? '-source_package' is not an option for a long time
#./mockgen.sh

echo
echo  "========= BEGIN TESTS ==========="
echo

for d in $(go list ./... | grep -E -v '/mock[^/]+$' ); do
    go test -v -race -tags test -coverprofile=profile.out -covermode=atomic "$d"
    if [ -f profile.out ]; then
        cat profile.out >> coverage.txt
        rm profile.out
    fi
done

echo
echo  "========= END TESTS ==========="
echo
