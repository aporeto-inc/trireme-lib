package datapathdriver

import (
	"go.aporeto.io/trireme-lib/controller/internal/datapathdriver/linux/iptablesctrl"
)

// Packet represents the actual packet and associated metadata exported by the driver
type Packet struct {
	packetPayload []byte
	mark          int
	packetID      int
}

type datapathpacketimpl struct{}

type datapathruleimpl struct {
	impl *iptablesctrl.Instance
}
type datapathimpl struct {
	datapathpacketimpl
	datapathruleimpl
}

type nfqCallbackData struct {
	data           interface{}
	packetCallback func(packet *Packet, callbackData interface{}) ([]byte, error)
}
