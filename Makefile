PROJECT_NAME := trireme
BUILD_NUMBER := latest
DOCKER_REGISTRY?=aporeto
DOCKER_IMAGE_NAME?=$(PROJECT_NAME)
DOCKER_IMAGE_TAG?=$(BUILD_NUMBER)

remote_enforcer:
	make -C ./cmd/
build:  remote_enforcer
	CGO_ENABLED=1 go build 

