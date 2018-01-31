#! /bin/bash -e

go get github.com/aporeto-inc/mock/mockgen
go get -u github.com/golang/mock/gomock
go get -u golang.org/x/tools/cmd/goimports

goimport_sanitize () {
  goimports $1 > $1.bk
  cat $1.bk | sed  $'s/^func /\/\/ nolint\\\nfunc /g' | sed  $'s/^type /\/\/ nolint\\\ntype /g' > $1
  rm -f $1.bk
}

echo "Cgnetcls Mocks"
mkdir -p utils/cgnetcls/mock
mockgen -source utils/cgnetcls/interfaces.go -destination utils/cgnetcls/mock/mockcgnetcls.go -package mockcgnetcls -source_package github.com/aporeto-inc/trireme-lib/utils/cgnetcls
goimport_sanitize utils/cgnetcls/mock/mockcgnetcls.go

echo "Controller/Internal/Supervisor/Provider Mocks"
mkdir -p controller/internal/supervisor/mock
mockgen -source controller/internal/supervisor/interfaces.go -destination controller/internal/supervisor/mock/mocksupervisor.go -package mocksupervisor
goimport_sanitize controller/internal/supervisor/mock/mocksupervisor.go

echo "Enforcer Mocks"
mkdir -p controller/internal/enforcer/mock
mockgen -source controller/internal/enforcer/interfaces.go -destination controller/internal/enforcer/mock/mockenforcer.go -package mockenforcer
goimport_sanitize controller/internal/enforcer/mock/mockenforcer.go

echo "Controller/Internal/ContextStore Mocks"
mkdir -p utils/contextstore/mock
mockgen -source utils/contextstore/interfaces.go -destination utils/contextstore/mock/mockcontextstore.go -package mockcontextstore
goimport_sanitize utils/contextstore/mock/mockcontextstore.go

echo "Controller/Internal/Processmon Mocks"
mkdir -p controller/internal/processmon/mock
mockgen -source controller/internal/processmon/interfaces.go -destination controller/internal/processmon/mock/mockprocessmon.go -package mockprocessmon
goimport_sanitize controller/internal/processmon/mock/mockprocessmon.go

echo "Controller/RemoteEnforcer Mocks"
mkdir -p controller/remoteenforcer/mock
mockgen -source controller/remoteenforcer/interfaces.go -destination controller/remoteenforcer/mock/mockremoteenforcer.go -package mockremoteenforcer
goimport_sanitize controller/remoteenforcer/mock/mockremoteenforcer.go

echo "Controller/RemoteEnforcer/StatsClient Mocks"
mkdir -p controller/remoteenforcer/internal/statsclient/mock
mockgen -source controller/remoteenforcer/internal/statsclient/interfaces.go -destination controller/remoteenforcer/internal/statsclient/mock/mockstatsclient.go -package mockstatsclient
goimport_sanitize controller/remoteenforcer/internal/statsclient/mock/mockstatsclient.go

echo "Controller/RemoteEnforcer/StatsCollector Mocks"
mkdir -p controller/remoteenforcer/internal/statscollector/mock
mockgen -source controller/remoteenforcer/internal/statscollector/interfaces.go -aux_files collector=collector/interfaces.go -destination controller/remoteenforcer/internal/statscollector/mock/mockstatscollector.go -package mockstatscollector
goimport_sanitize controller/remoteenforcer/internal/statscollector/mock/mockstatscollector.go

echo "Collector Mocks"
mkdir -p collector/mock
mockgen -source collector/interfaces.go -destination collector/mock/mockcollector.go -package mockcollector -source_package github.com/aporeto-inc/trireme-lib/collector
goimport_sanitize collector/mock/mockcollector.go

echo "Monitor Mocks"
mkdir -p monitor/mock
mockgen -source monitor/interfaces.go -destination monitor/mock/mockmonitor.go -package mockmonitor -source_package github.com/aporeto-inc/trireme-lib/monitor
goimport_sanitize monitor/mock/mockmonitor.go

echo "Monitor/Instance Mocks"
mkdir -p monitor/instance/mock
mockgen -source monitor/instance/interfaces.go -destination monitor/instance/mock/mockinstance.go -aux_files collector=collector/interfaces.go -package mockinstance -source_package github.com/aporeto-inc/trireme-lib//monitor/instance
goimport_sanitize monitor/instance/mock/mockinstance.go

echo "Monitor/RPC/Processor Mocks"
mkdir -p monitor/rpc/processor/mock
mockgen -source monitor/rpc/processor/interfaces.go -destination monitor/rpc/processor/mock/mockprocessor.go -aux_files collector=collector/interfaces.go -package mockprocessor -source_package github.com/aporeto-inc/trireme-lib/monitor/rpc/processor
goimport_sanitize monitor/rpc/processor/mock/mockprocessor.go

echo "RPC Wrapper Mocks"
mkdir -p controller/internal/enforcer/utils/rpcwrapper/mock 
mockgen -source controller/internal/enforcer/utils/rpcwrapper/interfaces.go -destination controller/internal/enforcer/utils/rpcwrapper/mock/mockrpcwrapper.go -package mockrpcwrapper -source_package github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/rpcwrapper 
goimport_sanitize controller/internal/enforcer/utils/rpcwrapper/mock/mockrpcwrapper.go

echo "Policy Interfaces Mock"
mkdir -p policy/mock
mockgen -source policy/interfaces.go -destination policy/mock/mockpolicy.go -package mockpolicy -source_package github.com/aporeto-inc/trireme-lib/policy
goimport_sanitize policy/mock/mockpolicy.go

echo "Trireme Controller Mock"
mkdir -p controller/mock
mockgen -source controller/interfaces.go -destination controller/mock/mocktrireme.go -package mockcontroller  -aux_files constants=constants/constants.go events=common/events.go policy=policy/interfaces.go processor=monitor/rpc/processor/interfaces.go supervisor=controller/internal/supervisor/interfaces.go -source_package github.com/aporeto-inc/trireme-lib/controller
goimport_sanitize mock/mocktrireme.go

echo >&2 "OK"
