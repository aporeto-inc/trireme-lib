// +build linux

package nfqdatapath

import (
	"testing"

	"github.com/magiconair/properties/assert"
	nfqueue "go.aporeto.io/netlink-go/nfqueue"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
)

// Go libraries

type nothing struct {
	verdict int
}

func (n *nothing) SetVerdict2(verdict uint32, mark uint32, packetLen uint32, packetID uint32, packet []byte) {
	n.verdict = 1
}

func createDatapath() *Datapath {
	secret, _ := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
	collector := &collector.DefaultCollector{}
	// mock the call
	prevRawSocket := GetUDPRawSocket
	defer func() {
		GetUDPRawSocket = prevRawSocket
	}()
	GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
		return nil, nil
	}
	enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})

	return enforcer
}

func TestNFQApplicationPathCorrectPkt(t *testing.T) {
	n := &nothing{}
	datapath := createDatapath()

	// SYN packet captured from 'telnet localhost 99'.
	// Everything is correct.
	buffer := []byte{0x45, 0x10, 0x00, 0x3c, 0xec, 0x6c, 0x40, 0x00, 0x40, 0x06, 0x50,
		0x3d, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x8c, 0x80, 0x00, 0x63, 0x2c, 0x32,
		0xa8, 0xd6, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xaa, 0xaa, 0xfe, 0x88, 0x00, 0x00, 0x02,
		0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0xff, 0xff, 0x44, 0xba, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x03, 0x03, 0x07}

	packet := &nfqueue.NFPacket{
		Buffer:      buffer,
		QueueHandle: n,
	}

	datapath.processApplicationPacketsFromNFQ(packet)
	assert.Equal(t, n.verdict, 1)
}

func TestNFQApplicationPathCorruptPkt(t *testing.T) {
	n := &nothing{}
	datapath := createDatapath()

	// Corrupt packet: less than min ipv4 packet
	buffer := []byte{0x45, 0x10, 0x00, 0x3c, 0xec, 0x6c, 0x40, 0x00, 0x40, 0x06, 0x50}

	packet := &nfqueue.NFPacket{
		Buffer:      buffer,
		QueueHandle: n,
	}

	datapath.processApplicationPacketsFromNFQ(packet)
	assert.Equal(t, n.verdict, 0)
}

func TestNFQNetworkPathCorrectPkt(t *testing.T) {
	n := &nothing{}
	datapath := createDatapath()

	// SYN packet captured from 'telnet localhost 99'.
	// Everything is correct.
	buffer := []byte{0x45, 0x10, 0x00, 0x3c, 0xec, 0x6c, 0x40, 0x00, 0x40, 0x06, 0x50,
		0x3d, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x8c, 0x80, 0x00, 0x63, 0x2c, 0x32,
		0xa8, 0xd6, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xaa, 0xaa, 0xfe, 0x88, 0x00, 0x00, 0x02,
		0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0xff, 0xff, 0x44, 0xba, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x03, 0x03, 0x07}

	packet := &nfqueue.NFPacket{
		Buffer:      buffer,
		QueueHandle: n,
	}

	datapath.processNetworkPacketsFromNFQ(packet)
	assert.Equal(t, n.verdict, 1)
}

func TestNFQNetworkPathCorruptPkt(t *testing.T) {
	n := &nothing{}
	datapath := createDatapath()

	// Corrupt packet: less than min ipv4 packet
	buffer := []byte{0x45, 0x10, 0x00, 0x3c, 0xec, 0x6c, 0x40, 0x00, 0x40, 0x06, 0x50}

	packet := &nfqueue.NFPacket{
		Buffer:      buffer,
		QueueHandle: n,
	}

	datapath.processNetworkPacketsFromNFQ(packet)
	assert.Equal(t, n.verdict, 0)
}
