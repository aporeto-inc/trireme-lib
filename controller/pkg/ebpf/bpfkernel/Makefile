DEBUG=1
UID=$(shell id -u)
PWD=$(shell pwd)

DOCKER_FILE?=Dockerfile
DOCKER_IMAGE?=aporeto/socket-filter


all: build-docker-image build-ebpf-object install-generated-go

build-docker-image:
	docker build -t $(DOCKER_IMAGE) -f $(DOCKER_FILE) .

build-ebpf-object:
	docker run --rm -e DEBUG=$(DEBUG) \
		-e CIRCLE_BUILD_URL=$(CIRCLE_BUILD_URL) \
		-v $(PWD):/src:ro \
		-v $(PWD)/ebpf:/dist/ \
		--workdir=/src \
		$(DOCKER_IMAGE) \
		make -f ebpf.mk build

install-generated-go:
	cp ebpf/socket-filter-bpf.go ../bpfbuild/socket-filter-bpf.go

delete-docker-image:
	docker rmi -f $(DOCKER_IMAGE)

lint:
	./tools/lint -ignorespelling "agre " -ignorespelling "AGRE " .
	./tools/shell-lint .
