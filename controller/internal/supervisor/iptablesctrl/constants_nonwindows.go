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
)
