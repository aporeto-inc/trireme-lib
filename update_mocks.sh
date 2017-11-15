#! /bin/bash -e

go get github.com/aporeto-inc/mock/mockgen
go get github.com/golang/mock/gomock

echo "Supervisor Mocks"
mockgen -source supervisor/interfaces.go -destination supervisor/mock/mocksupervisor.go -package mocksupervisor

echo "Internal/Processmon Mocks"
mockgen -source internal/processmon/interfaces.go -destination internal/processmon/mock/mockprocessmon.go -package mockprocessmon

echo "Internal/RemoteEnforcer Mocks"
mockgen -source internal/remoteenforcer/interfaces.go -destination internal/remoteenforcer/mock/mockremoteenforcer.go -package mockremoteenforcer

echo "Internal/RemoteEnforcer/StatsClient Mocks"
mockgen -source internal/remoteenforcer/internal/statsclient/interfaces.go -destination internal/remoteenforcer/internal/statsclient/mock/mockstatsclient.go -package mockstatsclient

echo "Internal/RemoteEnforcer/StatsCollector Mocks"
mockgen -source internal/remoteenforcer/internal/statscollector/interfaces.go -aux_files collector=collector/interfaces.go -destination internal/remoteenforcer/internal/statscollector/mock/mockstatscollector.go -package mockstatscollector

echo "Collector Mocks"
mockgen -source collector/interfaces.go -destination collector/mock/mockcollector.go -package mockcollector -source_package github.com/aporeto-inc/trireme-lib/collector

go get github.com/golang/mock/mockgen
echo >&2 "OK"
