#! /bin/bash -e

go get github.com/aporeto-inc/mock/mockgen 
go get github.com/aporeto-inc/mock/gomock

echo "Supervisor Mocks"
mockgen -source supervisor/interfaces.go -destination supervisor/mock/mock_interfaces.go -package mockinterfaces 

mockgen -source supervisor/iptablesutils/iptablesutils.go -destination supervisor/iptablesutils/mock/mockIptablesutils.go -package mockuptablesutils 

mockgen -source supervisor/provider/ipsetprovider.go -destination supervisor/provider/mock/mock_ipsetprovider.go -self_package github.com/aporeto-inc/trireme/supervisor/provider -package mockprovider 

mockgen -source supervisor/provider/iptablesprovider.go -destination supervisor/provider/mock/mockIptablesprovider.go -package mockprovider 

echo >&2 "OK"
