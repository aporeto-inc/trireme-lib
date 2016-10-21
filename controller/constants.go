package controller

const (
	triremeChainPrefix                = "TRIREME-"
	triremeAppPacketIPTableContext    = "raw"
	triremeAppAckPacketIPTableContext = "mangle"
	triremeAppPacketIPTableSection    = "PREROUTING"
	triremeAppChainPrefix             = triremeChainPrefix + "App-"
	triremeNetPacketIPTableContext    = "mangle"
	triremeNetPacketIPTableSection    = "POSTROUTING"
	triremeNetChainPrefix             = triremeChainPrefix + "Net-"
)
