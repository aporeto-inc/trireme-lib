#!/usr/bin/env bash

set -e
echo "" > coverage.txt

./mockgen.sh
./fix_bpf

## FIX ME. go1.14 automatically enables unsafe ptr checks when doing race checks,
## and it is not clear if this is compatible (it is disabled on Windows)

## this needs to be revisited and maybe remove "-gcflags=all=-d=checkptr=0" below
## once we determine if there is a real pointer issue in the tests. 

## this package fails when ptr checking is enabled:
## go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn  

## to see the failure, test that package individually with "checkptr=1"

CHECKPTR="-gcflags=all=-d=checkptr=0"

for d in $(go list ./... | grep -v 'mock|bpf'); do
    go test ${CHECKPTR} -race -tags test -coverprofile=profile.out -covermode=atomic $d
    if [ -f profile.out ]; then
        cat profile.out >> coverage.txt
        rm profile.out
    fi
done
