// +build windows

package iptablesctrl

const (
	ipTableSectionOutput     = "OUTPUT"
	ipTableSectionPreRouting = "PREROUTING"
	appPacketIPTableContext  = "OUTPUT"
	netPacketIPTableContext  = "INPUT"
	appProxyIPTableContext   = "OUTPUT"
)
