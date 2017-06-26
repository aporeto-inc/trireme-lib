#! /bin/bash -e

go get github.com/aporeto-inc/mock/mockgen
go get github.com/aporeto-inc/mock/gomock

echo "Supervisor Mocks"
mockgen -source supervisor/interfaces.go -destination supervisor/mock/mock_interfaces.go -package mockinterfaces

mockgen -source supervisor/iptablesutils/iptablesutils.go -destination supervisor/iptablesutils/mock/mockIptablesutils.go -package mockuptablesutils

mockgen -source supervisor/provider/ipsetprovider.go -destination supervisor/provider/mock/mock_ipsetprovider.go -self_package github.com/aporeto-inc/trireme/supervisor/provider -package mockprovider

mockgen -source supervisor/provider/iptablesprovider.go -destination supervisor/provider/mock/mockIptablesprovider.go -package mockprovider

echo "PacketGen Mocks"
mockgen -source enforcer/utils/packetgen/interfaces.go -destination enforcer/utils/packetgen/mock/mock_packetgen.go -package mockpacketgen -self_package github.com/aporeto-inc/trireme/enforcer/utils/packetgen -imports packetgen=github.com/aporeto-inc/trireme/enforcer/utils/packetgen

echo "Reporting interfaces"
mockgen -source collector/interfaces.go -destination mock/mock_reporting.go -package mockreporter -self_package github.com/aporeto-inc/trireme/collector -imports reporter=github.com/aporeto-inc/trireme/collector

echo >&2 "OK"
