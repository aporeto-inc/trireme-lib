// +build linux

package nfqdatapath

import (
	"net"
	"sync"

	"github.com/ghedo/go.pkt/packet"
)

type fakeConn struct {
	b []byte

	sync.RWMutex
}

func (f *fakeConn) Close() error {
	return nil
}

func (f *fakeConn) Write(b []byte) (int, error) {
	f.Lock()
	defer f.Unlock()

	f.b = b
	return len(b), nil
}

func (f *fakeConn) data() []byte {
	f.RLock()
	defer f.RUnlock()

	return f.b
}

func (f *fakeConn) ConstructWirePacket(srcIP, dstIP net.IP, transport packet.Packet, payload packet.Packet) ([]byte, error) {
	return packLayers(srcIP, dstIP, transport, payload)
}
