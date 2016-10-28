PROJECT_NAME := trireme-example
BUILD_NUMBER := latest
DOCKER_REGISTRY?=aporeto
DOCKER_IMAGE_NAME?=$(PROJECT_NAME)
DOCKER_IMAGE_TAG?=$(BUILD_NUMBER)

build:
	rm -rf ${GOPATH}/src/k8s.io/kubernetes/vendor/github.com/golang/glog
	CGO_ENABLED=1 go build -a -installsuffix cgo
	make package

package:
	mv example docker/trireme-example

docker_build: build
	docker \
		build \
		-t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) docker

docker_push: docker_build
	docker \
		push \
		$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)
