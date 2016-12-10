#! /bin/bash -e

echo "Supervisor Mocks"
mockgen -source supervisor/interfaces.go -destination supervisor/mock/mock_interfaces.go
gofmt -w supervisor/mock/mock_interfaces.go

mockgen -source supervisor/iptablesutils/iptablesutils.go -destination supervisor/iptablesutils/mock/mock_iptablesutils.go
gofmt -w supervisor/iptablesutils/mock/mock_iptablesutils.go

mockgen -source supervisor/provider/ipsetprovider.go -destination supervisor/provider/mock/mock_ipsetprovider.go -self_package github.com/aporeto-inc/trireme/supervisor/provider
gofmt -w supervisor/provider/mock/mock_ipsetprovider.go

mockgen -source supervisor/provider/iptablesprovider.go -destination supervisor/provider/mock/mock_iptablesprovider.go
gofmt -w supervisor/provider/mock/mock_iptablesprovider.go

echo >&2 "OK"
