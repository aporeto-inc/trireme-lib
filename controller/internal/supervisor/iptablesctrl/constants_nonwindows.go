// +build !windows

package iptablesctrl

const (
	ipTableSectionOutput     = "OUTPUT"
	ipTableSectionPreRouting = "PREROUTING"
	appPacketIPTableContext  = "mangle"
	netPacketIPTableContext  = "mangle"
	appProxyIPTableContext   = "nat"

	portSetIpsetType      = ""
	proxySetPortIpsetType = ""

	customQOSChainNFHook = "POSTROUTING"
	customQOSChainTable  = "mangle"
	// CustomQOSChain is the name of the chain where users can install custom QOS rules
	CustomQOSChain = "POST-CUSTOM-QOS"
)
