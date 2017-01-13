PROJECT_NAME := trireme-example
BUILD_NUMBER := latest
DOCKER_REGISTRY?=aporeto
DOCKER_IMAGE_NAME?=$(PROJECT_NAME)
DOCKER_IMAGE_TAG?=$(BUILD_NUMBER)

remote_enforcer_build:
	make -C ../cmd/ build

build:  remote_enforcer_build
	CGO_ENABLED=1 go build -a -installsuffix cgo
	make package

package:
	mv example docker/trireme-example
	make -C ../cmd package
	mv $(GOPATH)/bin/remote_enforcer docker/remote_enforcer
	mv $(GOPATH)/bin/aporetolaunch docker/aporetolaunch

docker_build: build
	docker \
		build \
		-t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) docker

docker_push: docker_build
	docker \
		push \
		$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)
