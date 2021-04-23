
## all: default is to show the help text
.PHONY: all help
all: help

ci: test lint

## vet: run go vet on the source
vet:
	go vet ./...

## test: test with race checks
test:
	@ scripts/test.sh

## lint: run the linter
lint:
	@ scripts/lint.sh

#
# help uses all the ## marks for help text
#
.PHONY: help
## help: prints this help message
help:
	@ echo "Usage: "
	@ echo
	@ echo "Run 'make <target>' where <target> is one of:"
	@ echo
	@ sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /' | sort
