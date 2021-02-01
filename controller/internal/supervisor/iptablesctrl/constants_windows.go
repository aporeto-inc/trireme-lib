// +build windows

package iptablesctrl

const (
	ipTableSectionOutput     = "OUTPUT"
	ipTableSectionPreRouting = "PREROUTING"
	appPacketIPTableContext  = "OUTPUT"
	netPacketIPTableContext  = "INPUT"
	appProxyIPTableContext   = "OUTPUT"

	portSetIpsetType      = "hash:net"
	proxySetPortIpsetType = "hash:port"

	customQOSChainNFHook = "POSTROUTING"
	customQOSChainTable  = "mangle"
	// CustomQOSChain is the name of the chain where users can install custom QOS rules
	CustomQOSChain          = "POST-CUSTOM-QOS"
	netPacketIPTableContext = "INPUT"
)
