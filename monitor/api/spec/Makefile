PROTOS_PATH = protos

.PHONY: all protos

all: protos

# Please use version v1.3.3 of protobuf to compile: 
# go get -u github.com/golang/protobuf/proto@v1.3.3
# go get -u github.com/golang/protobuf/protoc-gen-go@v1.3.3
protos: $(PROTOS_PATH)/monitor.proto
	protoc -I $(PROTOS_PATH) --go_out=plugins=grpc:$(PROTOS_PATH) \
		$(PROTOS_PATH)/monitor.proto
