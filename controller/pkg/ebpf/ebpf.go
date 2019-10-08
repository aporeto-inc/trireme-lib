// +build cgo
package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
	"go.aporeto.io/trireme-lib/controller/pkg/ebpf/bpfbuild"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.uber.org/zap"
)

type flow struct {
	srcIP   uint32
	dstIP   uint32
	srcPort uint16
	dstPort uint16
}

var m *bpflib.Module
var session_map *bpflib.Map

func testmap() {

	var key flow
	var val flow

	for {
		time.Sleep(5 * time.Second)
		f, _ := m.LookupNextElement(session_map, nil, unsafe.Pointer(&key), unsafe.Pointer(&val))
		if f == true {
			s := fmt.Sprintf("%v", key.srcIP)
			zap.L().Error("map is not empty " + s)
		}
	}
}

func init() {
	if err := syscall.Mount("/sys/fs/bpf/", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		fmt.Println("fail to mount bpf")
	}

	buf, err := bpfbuild.Asset("tcptracer-ebpf.o")
	if err != nil {
		fmt.Println("couldnt find asset. exit")
		os.Exit(1)
	}
	reader := bytes.NewReader(buf)

	m = bpflib.NewModuleFromReader(reader)
	if m == nil {
		fmt.Println("bpf not supported")
		os.Exit(1)
	}

	if err = m.Load(nil); err != nil {
		fmt.Println("error loading ", err)
		os.Exit(1)
	}

	sfAppAck := m.SocketFilter("socket/app_ack")
	if sfAppAck == nil {
		fmt.Println("Error creating socket")
		os.Exit(1)
	}

	if err := bpflib.PinObject(sfAppAck.Fd(), "/sys/fs/bpf/app-ack"); err != nil {
		fmt.Println("error pinning ", err)
		os.Exit(1)
	}

	sfNetSynAck := m.SocketFilter("socket/net_syn_ack")
	if sfNetSynAck == nil {
		fmt.Println("Error creating socket")
		os.Exit(1)
	}

	if err := bpflib.PinObject(sfNetSynAck.Fd(), "/sys/fs/bpf/net-syn-ack"); err != nil {
		fmt.Println("error pinning ", err)
		os.Exit(1)
	}

	session_map = m.Map("sessions")

	if session_map == nil {
		fmt.Println("error getting map")
		os.Exit(1)
	}
}

func CreateFlow(packet *packet.Packet) {
	var key flow
	var val uint8

	key.srcIP = binary.BigEndian.Uint32(packet.SourceAddress())
	key.dstIP = binary.BigEndian.Uint32(packet.DestinationAddress())
	key.srcPort = packet.SourcePort()
	key.dstPort = packet.DestPort()

	val = 1

	m.UpdateElement(session_map, unsafe.Pointer(&key), unsafe.Pointer(&val), 0)
}

func RemoveFlow(packet *packet.Packet) {
	var key flow

	key.srcIP = binary.BigEndian.Uint32(packet.SourceAddress())
	key.dstIP = binary.BigEndian.Uint32(packet.DestinationAddress())
	key.srcPort = packet.SourcePort()
	key.dstPort = packet.DestPort()

	m.DeleteElement(session_map, unsafe.Pointer(&key))
}
