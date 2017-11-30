#! /bin/bash -e

go get -u github.com/aporeto-inc/mock/mockgen
go get -u github.com/golang/mock/gomock
go get -u golang.org/x/tools/cmd/goimports

goimport_sanitize () {
  goimports $1 > $1.bk
  cat $1.bk | sed  $'s/^func /\/\/ nolint\\\nfunc /g' | sed  $'s/^type /\/\/ nolint\\\ntype /g' > $1
  rm -f $1.bk
}

echo "Enforcer/PolicyEnforcer Mocks"
mockgen -source enforcer/policyenforcer/interfaces.go -destination enforcer/policyenforcer/mock/mockpolicyenforcer.go -package mockpolicyenforcer -source_package github.com/aporeto-inc/trireme-lib/enforcer
goimport_sanitize enforcer/policyenforcer/mock/mockpolicyenforcer.go

echo "Supervisor Mocks"
mockgen -source supervisor/interfaces.go -destination supervisor/mock/mocksupervisor.go -package mocksupervisor
goimport_sanitize supervisor/mock/mocksupervisor.go

echo "Internal/ContextStore Mocks"
mockgen -source internal/contextstore/interfaces.go -destination internal/contextstore/mock/mockcontextstore.go -package mockcontextstore
goimport_sanitize internal/contextstore/mock/mockcontextstore.go

echo "Internal/Processmon Mocks"
mockgen -source internal/processmon/interfaces.go -destination internal/processmon/mock/mockprocessmon.go -package mockprocessmon
goimport_sanitize internal/processmon/mock/mockprocessmon.go

echo "Internal/RemoteEnforcer Mocks"
mockgen -source internal/remoteenforcer/interfaces.go -destination internal/remoteenforcer/mock/mockremoteenforcer.go -package mockremoteenforcer
goimport_sanitize internal/remoteenforcer/mock/mockremoteenforcer.go

echo "Internal/RemoteEnforcer/StatsClient Mocks"
mockgen -source internal/remoteenforcer/internal/statsclient/interfaces.go -destination internal/remoteenforcer/internal/statsclient/mock/mockstatsclient.go -package mockstatsclient
goimport_sanitize internal/remoteenforcer/internal/statsclient/mock/mockstatsclient.go

echo "Internal/RemoteEnforcer/StatsCollector Mocks"
mockgen -source internal/remoteenforcer/internal/statscollector/interfaces.go -aux_files collector=collector/interfaces.go -destination internal/remoteenforcer/internal/statscollector/mock/mockstatscollector.go -package mockstatscollector
goimport_sanitize internal/remoteenforcer/internal/statscollector/mock/mockstatscollector.go

echo "Collector Mocks"
mockgen -source collector/interfaces.go -destination collector/mock/mockcollector.go -package mockcollector -source_package github.com/aporeto-inc/trireme-lib/collector
goimport_sanitize collector/mock/mockcollector.go

echo "Monitor Mocks"
mockgen -source monitor/interfaces.go -destination monitor/mock/mockmonitor.go -aux_files policy=policy/interfaces.go eventinfo=monitor/eventinfo/eventinfo.go -package mockmonitor -source_package github.com/aporeto-inc/trireme-lib/monitor
goimport_sanitize monitor/mock/mockmonitor.go

echo "Monitor/Processor Mocks"
mockgen -source monitor/processor/interfaces.go -destination monitor/processor/mock/mockprocessor.go -package mockprocessor -source_package github.com/aporeto-inc/trireme-lib/monitor/processor
goimport_sanitize monitor/processor/mock/mockprocessor.go

echo >&2 "OK"
