#! /bin/bash -e

GO111MODULE=on go get github.com/golang/mock/mockgen@latest
go get github.com/golang/mock/mockgen/model
go get -u golang.org/x/tools/cmd/goimports

goimport_sanitize () {
  tmp=$(mktemp)
  goimports "$1" > "$tmp"
  sed  $'s/^func /\/\/ nolint\\\nfunc /g' < "$tmp" | sed  $'s/^type /\/\/ nolint\\\ntype /g' > "$1"
  rm -f "$tmp"
}

echo "Cgnetcls Mocks"
mkdir -p utils/cgnetcls/mockcgnetcls
mockgen -source utils/cgnetcls/interfaces.go -destination utils/cgnetcls/mockcgnetcls/mockcgnetcls.go -package mockcgnetcls
goimport_sanitize utils/cgnetcls/mockcgnetcls/mockcgnetcls.go

echo "Controller/internal/supervisor/Provider Mocks"
mkdir -p controller/internal/supervisor/mocksupervisor
mockgen -source controller/internal/supervisor/interfaces.go -destination controller/internal/supervisor/mocksupervisor/mocksupervisor.go -package mocksupervisor
goimport_sanitize controller/internal/supervisor/mocksupervisor/mocksupervisor.go

echo "Enforcer Mocks"
mkdir -p controller/internal/enforcer/mockenforcer
mockgen -source controller/internal/enforcer/enforcer.go -destination controller/internal/enforcer/mockenforcer/mockenforcer.go -package mockenforcer
goimport_sanitize controller/internal/enforcer/mockenforcer/mockenforcer.go

echo "Controller/Processmon Mocks"
mkdir -p controller/internal/processmon/mockprocessmon
mockgen -source controller/internal/processmon/interfaces.go -destination controller/internal/processmon/mockprocessmon/mockprocessmon.go -package mockprocessmon
goimport_sanitize controller/internal/processmon/mockprocessmon/mockprocessmon.go

echo "controller/pkg/remoteenforcer Mocks"
mkdir -p controller/pkg/remoteenforcer/mockremoteenforcer
mockgen -source controller/pkg/remoteenforcer/interfaces.go -destination controller/pkg/remoteenforcer/mockremoteenforcer/mockremoteenforcer.go -package mockremoteenforcer
goimport_sanitize controller/pkg/remoteenforcer/mockremoteenforcer/mockremoteenforcer.go

echo "controller/pkg/remoteenforcer/client Mocks"
mkdir -p controller/pkg/remoteenforcer/internal/client/mockclient
mockgen -source controller/pkg/remoteenforcer/internal/client/interfaces.go -destination controller/pkg/remoteenforcer/internal/client/mockclient/mockclient.go -package mockclient
goimport_sanitize controller/pkg/remoteenforcer/internal/client/mockclient/mockclient.go

echo "controller/pkg/remoteenforcer/TokenIssuer Mocks"
mkdir -p controller/pkg/remoteenforcer/internal/tokenissuer/mocktokenclient
mockgen -source controller/pkg/remoteenforcer/internal/tokenissuer/tokenissuer.go -destination controller/pkg/remoteenforcer/internal/tokenissuer/mocktokenclient/mocktokenclient.go -package mocktokenclient
goimport_sanitize controller/pkg/remoteenforcer/internal/tokenissuer/mocktokenclient/mocktokenclient.go

echo "controller/pkg/remoteenforcer/StatsCollector Mocks"
mkdir -p controller/pkg/remoteenforcer/internal/statscollector/mockstatscollector
mockgen \
-source controller/pkg/remoteenforcer/internal/statscollector/interfaces.go \
-destination controller/pkg/remoteenforcer/internal/statscollector/mockstatscollector/mockstatscollector.go \
-package mockstatscollector \
-aux_files collector=collector/interfaces.go \
-imports statscollector=go.aporeto.io/trireme-lib/v11/controller/pkg/remoteenforcer/internal/statscollector
goimport_sanitize controller/pkg/remoteenforcer/internal/statscollector/mockstatscollector/mockstatscollector.go

echo "controller/pkg/usertokens Mocks"
mkdir -p controller/pkg/usertokens/mockusertokens
mockgen -source controller/pkg/usertokens/usertokens.go -destination controller/pkg/usertokens/mockusertokens/mockusertokens.go -package mockusertokens
goimport_sanitize controller/pkg/usertokens/mockusertokens/mockusertokens.go

echo "Collector Mocks"
mkdir -p collector/mockcollector
mockgen -source collector/interfaces.go -destination collector/mockcollector/mockcollector.go -package mockcollector
goimport_sanitize collector/mockcollector/mockcollector.go

echo "Monitor Mocks"
mkdir -p monitor/mockmonitor
mockgen -source monitor/interfaces.go -destination monitor/mockmonitor/mockmonitor.go -package mockmonitor
goimport_sanitize monitor/mockmonitor/mockmonitor.go

echo "Monitor remoteapi client mocks"
mkdir -p monitor/remoteapi/client/mockclient
mockgen -source monitor/remoteapi/client/interfaces.go -destination monitor/remoteapi/client/mockclient/mockclient.go -package mockclient
goimport_sanitize monitor/remoteapi/client/mockclient/mockclient.go

echo "Monitor/processor Mocks"
mkdir -p monitor/processor/mockprocessor
mockgen -source monitor/processor/interfaces.go -destination monitor/processor/mockprocessor/mockprocessor.go -aux_files collector=collector/interfaces.go -package mockprocessor
goimport_sanitize monitor/processor/mockprocessor/mockprocessor.go

echo "controller/internal/enforcer/nfqdatapath/tokenaccessor Mocks"
mkdir -p controller/internal/enforcer/nfqdatapath/tokenaccessor/mocktokenaccessor
mockgen -source controller/internal/enforcer/nfqdatapath/tokenaccessor/interfaces.go -destination controller/internal/enforcer/nfqdatapath/tokenaccessor/mocktokenaccessor/mocktokenaccessor.go -package mocktokenaccessor
goimport_sanitize controller/internal/enforcer/nfqdatapath/tokenaccessor/mocktokenaccessor/mocktokenaccessor.go

echo "controller/pkg/tokens Mocks"
mkdir -p controller/pkg/tokens/mocktokens
mockgen -source controller/pkg/tokens/tokens.go -destination controller/pkg/tokens/mocktokens/mocktokens.go -package mocktokens
goimport_sanitize controller/pkg/tokens/mocktokens/mocktokens.go

echo "RPC Wrapper Mocks"
mkdir -p controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper
mockgen -source controller/internal/enforcer/utils/rpcwrapper/interfaces.go -destination controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper/mockrpcwrapper.go -package mockrpcwrapper
goimport_sanitize controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper/mockrpcwrapper.go

echo "Policy Interfaces Mock"
mkdir -p policy/mockpolicy
mockgen -source policy/interfaces.go -destination policy/mockpolicy/mockpolicy.go -package mockpolicy
goimport_sanitize policy/mockpolicy/mockpolicy.go

echo "Trireme Controller Mock"
mkdir -p controller/mockcontroller
mockgen -source controller/interfaces.go -destination controller/mockcontroller/mocktrireme.go -package mockcontroller  -aux_files constants=controller/constants/constants.go events=common/events.go policy=policy/interfaces.go processor=monitor/processor/interfaces.go supervisor=controller/internal/supervisor/interfaces.go
goimport_sanitize controller/mockcontroller/mocktrireme.go

echo "Pod Monitor Mocks (manager, client and zap core)"
# NOTE: this uses interface mode because these are all 3rd party dependencies
mockgen -package podmonitor -destination monitor/internal/pod/mockzapcore_test.go go.uber.org/zap/zapcore Core
goimport_sanitize monitor/internal/pod/mockzapcore_test.go
mockgen -package podmonitor -destination monitor/internal/pod/mockclient_test.go sigs.k8s.io/controller-runtime/pkg/client Client
goimport_sanitize monitor/internal/pod/mockclient_test.go
mockgen -package podmonitor -destination monitor/internal/pod/mockcache_test.go sigs.k8s.io/controller-runtime/pkg/cache Cache
goimport_sanitize monitor/internal/pod/mockcache_test.go
mockgen -package podmonitor -destination monitor/internal/pod/mockinformer_test.go sigs.k8s.io/controller-runtime/pkg/cache Informer
goimport_sanitize monitor/internal/pod/mockinformer_test.go
# mockgen -package podmonitor -destination monitor/internal/pod/mockinformer_test.go k8s.io/client-go/tools/cache SharedIndexInformer
# goimport_sanitize monitor/internal/pod/mockinformer_test.go
mockgen -package podmonitor -destination monitor/internal/pod/mockmanager_test.go sigs.k8s.io/controller-runtime/pkg/manager Manager
goimport_sanitize monitor/internal/pod/mockmanager_test.go

echo >&2 "OK"
