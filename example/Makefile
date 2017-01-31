PROJECT_NAME := trireme-example
BUILD_NUMBER := latest
DOCKER_REGISTRY?=aporeto
DOCKER_IMAGE_NAME?=$(PROJECT_NAME)
DOCKER_IMAGE_TAG?=$(BUILD_NUMBER)
BIN_PATH := /usr/local/bin

build:
	glide install
	CGO_ENABLED=1 go build -a -installsuffix cgo

install: build
	  sudo cp example $(BIN_PATH)/trireme

package:
	cp example docker/trireme
	mv example trireme

docker_build: build
	docker \
		build \
		-t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) docker

docker_push: docker_build
	docker \
		push \
		$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)

clean:
	rm -rf vendor
	rm -rf example
	rm -rf docker/trireme
