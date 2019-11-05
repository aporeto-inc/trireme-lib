// +build !linux

package iptablesctrl

const (
	chainPrefix         = "TRI-"
	mainAppChain        = chainPrefix + "App"
	mainNetChain        = chainPrefix + "Net"
	uidchain            = chainPrefix + "UID-App"
	uidInput            = chainPrefix + "UID-Net"
	appChainPrefix      = chainPrefix + "App-"
	netChainPrefix      = chainPrefix + "Net-"
	natProxyOutputChain = chainPrefix + "Redir-App"
	natProxyInputChain  = chainPrefix + "Redir-Net"
	proxyOutputChain    = chainPrefix + "Prx-App"
	proxyInputChain     = chainPrefix + "Prx-Net"

	targetTCPNetworkSet  = "TargetTCP"
	targetUDPNetworkSet  = "TargetUDP"
	excludedNetworkSet   = "Excluded"
	uidPortSetPrefix     = "UID-Port-"
	processPortSetPrefix = "ProcPort-"
	proxyPortSetPrefix   = "Proxy-"
	// TriremeInput represent the chain that contains pu input rules.
	TriremeInput = chainPrefix + "Pid-Net"
	// TriremeOutput represent the chain that contains pu output rules.
	TriremeOutput = chainPrefix + "Pid-App"

	// NetworkSvcInput represent the chain that contains NetworkSvc input rules.
	NetworkSvcInput = chainPrefix + "Svc-Net"

	// NetworkSvcOutput represent the chain that contains NetworkSvc output rules.
	NetworkSvcOutput = chainPrefix + "Svc-App"

	// HostModeInput represent the chain that contains Hostmode input rules.
	HostModeInput = chainPrefix + "Hst-Net"

	// HostModeOutput represent the chain that contains Hostmode output rules.
	HostModeOutput = chainPrefix + "Hst-App"

	ipTableSectionOutput     = "OUTPUT"
	ipTableSectionPreRouting = "PREROUTING"
	appPacketIPTableContext  = "OUTPUT"
	netPacketIPTableContext  = "INPUT"
	appProxyIPTableContext   = "OUTPUT"

	proxyMark = "0x40"
)
