#! /bin/bash -e

go get github.com/golang/mock/mockgen
go get github.com/golang/mock/gomock

echo "Supervisor Mocks"
mockgen -source supervisor/interfaces.go -destination supervisor/mock/mock_interfaces.go -package mockinterfaces

echo "Processmon Mocks"
mockgen -source internal/processmon/interfaces.go -destination internal/processmon/mock/mockprocessmon.go -package mockprocessmon

echo >&2 "OK"
