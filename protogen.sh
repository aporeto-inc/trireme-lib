#!/bin/bash

CUR_DIR="$(pwd)"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

ENVOY_REPO="github.com/envoyproxy/data-plane-api"
ENVOY_REPO_PKG="go.aporeto.io/trireme-lib/third_party/generated/envoyproxy/data-plane-api"
PB_OUT="${DIR}/third_party/generated/envoyproxy/data-plane-api"
# gogofaster and gogoslick don't work unfortunately
# also, they currently don't work with validate
PB_GENERATOR="gogofast"

PROTOC="$(which protoc)"
if [ $? -ne 0 ] ; then
  echo "ERROR: protoc needs to be installed and in the PATH" 1>&2
  exit 2
fi

PB_GENERATOR_BIN="$(which protoc-gen-${PB_GENERATOR})"
if [ $? -ne 0 ] ; then
  echo "ERROR: protoc-gen-${PB_GENERATOR} needs to be installed and in the PATH" 1>&2
  exit 2
fi

echo "Protobuf compilers are at:"
echo "PROTOC=${PROTOC}"
echo "PB_GENERATOR_BIN=${PB_GENERATOR_BIN}"
echo

echo "Ensuring output folder exists: ${PB_OUT}"
mkdir -v -p ${PB_OUT}
echo

echo "Updating / Downloading necessary packages and repo..."
go get -u -v google.golang.org/grpc
go get -u -v github.com/gogo/protobuf/types
go get -u -v github.com/gogo/googleapis/google/rpc
go get -u -v github.com/envoyproxy/protoc-gen-validate
echo "NOTE: it is okay for this to fail, there is no go code in here"
go get -v -u -d ${ENVOY_REPO}
echo

# useful when you need to find out dependencies and things for mapping
#  --descriptor_set_out=${PB_OUT}/${input}.descriptor_set \
#  --include_imports \
#  --dependency_out=${PB_OUT}/${input}.dependencies \
# validate currently doesn't work
#  --validate_out=lang=go:${PB_OUT} \
PROTOC_CMD="
${PROTOC} \
  -I${GOPATH:-${HOME/go}}/src/${ENVOY_REPO} \
  -I${GOPATH:-${HOME/go}}/src/github.com/gogo/protobuf/protobuf \
  -I${GOPATH:-${HOME/go}}/src/github.com/gogo/protobuf \
  -I${GOPATH:-${HOME/go}}/src/github.com/gogo/googleapis \
  -I${GOPATH:-${HOME/go}}/src/github.com/envoyproxy/protoc-gen-validate \
  --${PB_GENERATOR}_out=plugins=\
grpc,\
Menvoy/type/percent.proto=${ENVOY_REPO_PKG}/envoy/type,\
Menvoy/type/http_status.proto=${ENVOY_REPO_PKG}/envoy/type,\
Menvoy/api/v2/core/base.proto=${ENVOY_REPO_PKG}/envoy/api/v2/core,\
Menvoy/api/v2/core/address.proto=${ENVOY_REPO_PKG}/envoy/api/v2/core,\
Mgoogle/rpc/status.proto=github.com/gogo/googleapis/google/rpc,\
Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/duration.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/struct.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/wrappers.proto=github.com/gogo/protobuf/types\
:${PB_OUT} \
"

echo "Changing working directory to the envoy repo..."
cd ${GOPATH:-${HOME/go}}/src/${ENVOY_REPO}

echo "running protoc for dependencies from envoy/type..."
$PROTOC_CMD \
  envoy/type/http_status.proto \
  envoy/type/percent.proto
echo

echo "running protoc for dependencies from envoy/api/v2/core..."
$PROTOC_CMD \
  envoy/api/v2/core/address.proto \
  envoy/api/v2/core/base.proto
echo

echo "running protoc for ext_authz_v2..."
$PROTOC_CMD \
  envoy/service/auth/v2/attribute_context.proto \
  envoy/service/auth/v2/external_auth.proto
echo

cd ${CUR_DIR}
