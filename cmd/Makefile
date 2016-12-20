PROJECT_NAME := remote_enforcer
BUILD_NUMBER := latest
DOCKER_REGISTRY?=aporeto
DOCKER_IMAGE_NAME?=$(PROJECT_NAME)
DOCKER_IMAGE_TAG?=$(BUILD_NUMBER)

build: remote_enforcer.go
	CGO_ENABLED=1 go build -o $(PROJECT_NAME) 

package:
	@mkdir -p $(GOPATH)/bin
	mv  $(PROJECT_NAME) $(GOPATH)/bin/$(PROJECT_NAME)
