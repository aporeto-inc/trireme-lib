// +build darwin !linux

package nflog

// nfLog TODO
type nfLog struct {
}

func newNfLog(mcastGroup int, ipVersion byte, direction IPDirection, maskBits int, packetsInput, packetsOutput chan []Packet) (*nfLog, error) {
	return nil, nil
}

func (n *nfLog) start() {}
func (n *nfLog) stop()  {}
