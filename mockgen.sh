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
mkdir -p utils/cgnetcls/mockcgnetcls
mockgen -source utils/cgnetcls/interfaces.go -destination utils/cgnetcls/mockcgnetcls/mockcgnetcls.go -package mockcgnetcls -source_package go.aporeto.io/trireme-lib/utils/cgnetcls
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

echo "controller/pkg/remoteenforcer/StatsClient Mocks"
mkdir -p controller/pkg/remoteenforcer/internal/statsclient/mockstatsclient
mockgen -source controller/pkg/remoteenforcer/internal/statsclient/interfaces.go -destination controller/pkg/remoteenforcer/internal/statsclient/mockstatsclient/mockstatsclient.go -package mockstatsclient
goimport_sanitize controller/pkg/remoteenforcer/internal/statsclient/mockstatsclient/mockstatsclient.go


echo "controller/pkg/remoteenforcer/CounterClient Mocks"
mkdir -p controller/pkg/remoteenforcer/internal/counterclient/mockcounterclient
mockgen -source controller/pkg/remoteenforcer/internal/counterclient/interfaces.go -destination controller/pkg/remoteenforcer/internal/counterclient/mockcounterclient/mockcounterclient.go -package mockcounterclient
goimport_sanitize controller/pkg/remoteenforcer/internal/counterclient/mockcounterclient/mockcounterclient.go

echo "controller/pkg/remoteenforcer/TokenIssuer Mocks"
mkdir -p controller/pkg/remoteenforcer/internal/tokenissuer/mocktokenclient
mockgen -source controller/pkg/remoteenforcer/internal/tokenissuer/tokenissuer.go -destination controller/pkg/remoteenforcer/internal/tokenissuer/mocktokenclient/mocktokenclient.go -package mocktokenclient
goimport_sanitize controller/pkg/remoteenforcer/internal/tokenissuer/mocktokenclient/mocktokenclient.go

echo "controller/pkg/remoteenforcer/DebugClient Mocks"
mkdir -p controller/pkg/remoteenforcer/internal/debugclient/mockdebugclient
mockgen -source controller/pkg/remoteenforcer/internal/debugclient/interfaces.go -destination controller/pkg/remoteenforcer/internal/debugclient/mockdebugclient/mockdebugclient.go -package mockdebugclient
goimport_sanitize controller/pkg/remoteenforcer/internal/debugclient/mockdebugclient/mockdebugclient.go

echo "controller/pkg/remoteenforcer/StatsCollector Mocks"
mkdir -p controller/pkg/remoteenforcer/internal/statscollector/mockstatscollector
mockgen -source controller/pkg/remoteenforcer/internal/statscollector/interfaces.go -aux_files collector=collector/interfaces.go -destination controller/pkg/remoteenforcer/internal/statscollector/mockstatscollector/mockstatscollector.go -package mockstatscollector
goimport_sanitize controller/pkg/remoteenforcer/internal/statscollector/mockstatscollector/mockstatscollector.go

echo "controller/pkg/usertokens Mocks"
mkdir -p controller/pkg/usertokens/mockusertokens
mockgen -source controller/pkg/usertokens/usertokens.go -destination controller/pkg/usertokens/mockusertokens/mockusertokens.go -package mockusertokens
goimport_sanitize controller/pkg/usertokens/mockusertokens/mockusertokens.go

echo "Collector Mocks"
mkdir -p collector/mockcollector
mockgen -source collector/interfaces.go -destination collector/mockcollector/mockcollector.go -package mockcollector -source_package go.aporeto.io/trireme-lib/collector
goimport_sanitize collector/mockcollector/mockcollector.go

echo "Monitor Mocks"
mkdir -p monitor/mockmonitor
mockgen -source monitor/interfaces.go -destination monitor/mockmonitor/mockmonitor.go -package mockmonitor -source_package go.aporeto.io/trireme-lib/monitor
goimport_sanitize monitor/mockmonitor/mockmonitor.go

echo "Monitor/processor Mocks"
mkdir -p monitor/processor/mockprocessor
mockgen -source monitor/processor/interfaces.go -destination monitor/processor/mockprocessor/mockprocessor.go -aux_files collector=collector/interfaces.go -package mockprocessor -source_package go.aporeto.io/trireme-lib/monitor/processor
goimport_sanitize monitor/processor/mockprocessor/mockprocessor.go

echo "RPC Wrapper Mocks"
mkdir -p controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper 
mockgen -source controller/internal/enforcer/utils/rpcwrapper/interfaces.go -destination controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper/mockrpcwrapper.go -package mockrpcwrapper -source_package go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper 
goimport_sanitize controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper/mockrpcwrapper.go

echo "Policy Interfaces Mock"
mkdir -p policy/mockpolicy
mockgen -source policy/interfaces.go -destination policy/mockpolicy/mockpolicy.go -package mockpolicy -source_package go.aporeto.io/trireme-lib/policy
goimport_sanitize policy/mockpolicy/mockpolicy.go

echo "Trireme Controller Mock"
mkdir -p controller/mockcontroller
mockgen -source controller/interfaces.go -destination controller/mockcontroller/mocktrireme.go -package mockcontroller  -aux_files constants=controller/constants/constants.go events=common/events.go policy=policy/interfaces.go processor=monitor/processor/interfaces.go supervisor=controller/internal/supervisor/interfaces.go -source_package go.aporeto.io/trireme-lib/controller
goimport_sanitize controller/mockcontroller/mocktrireme.go

echo >&2 "OK"
