#!/usr/bin/env bash

# use wine to execute if not running tests on a Windows machine
OS=`uname -s`
if [[ $OS == *"NT-"* ]]; then
	WINE_EXEC=
else
	WINE_EXEC=-exec wine
fi

set -e
echo "" > coverage.windows.txt

for d in $(CGO_ENABLED=0 go list ./... | grep -v remoteenforcer | grep -v remoteapi | grep -v "plugins/pam"); do
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -tags test $WINE_EXEC -coverprofile=profile.windows.out -covermode=atomic $d
    if [ -f profile.windows.out ]; then
        cat profile.windows.out >> coverage.windows.txt
        rm profile.windows.out
    fi
done
