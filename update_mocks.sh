#! /bin/bash -e

go get github.com/aporeto-inc/mock/mockgen
go get github.com/golang/mock/gomock
go get golang.org/x/tools/cmd/goimports

goimport_sanitize () {
  goimports $1 > $1.bk
  mv $1.bk $1
}

echo "Supervisor Mocks"
mockgen -source supervisor/interfaces.go -destination supervisor/mock/mocksupervisor.go -package mocksupervisor
goimport_sanitize supervisor/mock/mocksupervisor.go

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

echo >&2 "OK"
