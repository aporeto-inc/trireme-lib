#! /bin/bash -e

go get github.com/aporeto-inc/mock/mockgen 
go get github.com/aporeto-inc/mock/gomock

echo "Supervisor Mocks"
mockgen -source supervisor/interfaces.go -destination supervisor/mock/mock_interfaces.go -package mockinterfaces 

echo >&2 "OK"
