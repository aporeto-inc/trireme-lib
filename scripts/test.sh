#!/usr/bin/env bash

export GO111MODULE=auto

## FIX ME. go1.14 automatically enables unsafe ptr checks when doing race checks,
## and it is not clear if this is compatible (it is disabled on Windows)
##
## This needs to be revisited and maybe remove "-gcflags=all=-d=checkptr=0" below
## for go1.14 once we determine if there is a real pointer issue in the tests.
##
## this is the file that fails when ptr checking is enabled:
## go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn_test.go
##
## to see the failure, test that package individually setting "checkptr=1"

case "$(go version)" in
    *1.13*) CHECKPTR=""  ;;
    *)      CHECKPTR="-gcflags=all=-d=checkptr=0" ;;
esac

# set -e
rm -f coverage.txt
touch coverage.txt

## FIX ME. go1.14 automatically enables unsafe ptr checks when doing race checks,
## and it is not clear if this is compatible (it is disabled on Windows)
##
## This needs to be revisited and maybe remove "-gcflags=all=-d=checkptr=0" below
## for go1.14 once we determine if there is a real pointer issue in the tests.
##
## this is the file that fails when ptr checking is enabled:
## go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn_test.go
##
## to see the failure, test that package individually setting "checkptr=1"

case "$(go version)" in
    *1.13*) CHECKPTR=""  ;;
    *)      CHECKPTR="-gcflags=all=-d=checkptr=0" ;;
esac

if [[ $# -gt 0 ]]; then
    pkglist="$*"
else
    pkglist="$(go list ./... | grep -E -v '(mock|bpf)')"
fi

echo
echo  "========= BEGIN LINUX TESTS ==========="
echo

for pkg in $pkglist ; do
    go test -tags test $CHECKPTR -race -coverprofile=profile.out -covermode=atomic "$pkg"
    if [ -f profile.out ]; then
        cat profile.out >> coverage.txt
        rm profile.out
    fi
done

echo
echo  "========= END LINUX TESTS ==========="
echo
