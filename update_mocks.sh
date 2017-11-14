#! /bin/bash -e

go get github.com/aporeto-inc/mock/mockgen
go get github.com/golang/mock/gomock

echo "Supervisor Mocks"
mockgen -source supervisor/interfaces.go -destination supervisor/mock/mocksupervisor.go -package mocksupervisor

echo "Processmon Mocks"
mockgen -source internal/processmon/interfaces.go -destination internal/processmon/mock/mockprocessmon.go -package mockprocessmon

echo "Collector Mocks"
mockgen -source collector/interfaces.go -destination collector/mock/mockcollector.go -package mockcollector -source_package github.com/aporeto-inc/trireme/collector

go get github.com/golang/mock/mockgen
echo >&2 "OK"
