// +build !linux

package enforcer

// NewNFLogger returns a new NFLogger.
func NewNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUInfo puInfoFunc, collector collector.EventCollector) *nfLogger {
return nil
}

func (*nfLogger) Start(){}
