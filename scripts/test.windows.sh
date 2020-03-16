#!/usr/bin/env bash

export GO111MODULES=auto
export CGO_ENABLED=0
export GOOS=windows
export GOARCH=amd64

# use wine to execute if not running tests on a Windows machine
OS="$(uname -s)"
if [[ "$OS" == *"NT-"* ]]; then
	WINE_EXEC=
else
	WINE_EXEC="-exec wine"
fi

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
rm -f coverage.windows.txt
touch coverage.windows.txt

echo
echo  "========= BEGIN WINDOWS TESTS ==========="
echo

for pkg in $(go list ./... | grep -v remoteenforcer | grep -v remoteapi | grep -v "plugins/pam"); do
    go test -tags test $WINE_EXEC $CHECKPTR -coverprofile=profile.windows.out -covermode=atomic "$pkg"
    if [ -f profile.windows.out ]; then
        cat profile.windows.out >> coverage.windows.txt
        rm profile.windows.out
    fi
done

echo
echo  "========= END WINDOWS TESTS ==========="
echo
