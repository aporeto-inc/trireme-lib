// +build !rhel6

package ebpf

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
	"github.com/iovisor/gobpf/pkg/bpffs"
	provider "go.aporeto.io/trireme-lib/v11/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/ebpf/bpfbuild"
	"go.uber.org/zap"
)

type ebpfModule struct {
	m          *bpflib.Module
	sessionMap *bpflib.Map
	bpfPath    string
}

type flow struct {
	srcIP   uint32
	dstIP   uint32
	srcPort uint16
	dstPort uint16
}

const bpfPath = "/sys/fs/bpf/"
const bpfPrefix = "app-ack"

func removeOldBPFFiles() {

	removeFiles := func(path string, info os.FileInfo, err error) error {
		if strings.Contains(path, bpfPrefix) {
			if err := os.Remove(path); err != nil {
				zap.L().Debug("Failed to remove file", zap.String("path", path), zap.Error(err))
			}
		}
		return nil
	}

	filepath.Walk(bpfPath, removeFiles) //nolint
}

// ISeBPFSupported is called once by the master enforcer to test if
// the system supports eBPF.
func ISeBPFSupported() bool {

	if err := bpffs.Mount(); err != nil {
		zap.L().Info("bpf mount failed", zap.Error(err))
		return false
	}

	var bpf BPFModule

	if bpf = LoadBPF(); bpf == nil {
		return false
	}

	if err := provider.TestIptablesPinned(bpf.GetBPFPath()); err != nil {
		zap.L().Info("Kernel doesn't support iptables pinned path", zap.Error(err))
		return false
	}

	removeOldBPFFiles()
	return true
}

//LoadBPF loads the bpf object in the memory and also pins the bpf to the file system.
func LoadBPF() BPFModule {
	bpf := &ebpfModule{}

	bpf.bpfPath = bpfPath + bpfPrefix + strconv.Itoa(os.Getpid())
	if err := os.Remove(bpf.bpfPath); err != nil {
		zap.L().Debug("Failed to remove bpf file", zap.Error(err))
	}

	buf, err := bpfbuild.Asset("socket-filter-bpf.o")
	if err != nil {
		zap.L().Info("Failed to locate asset socket-filter-bpf", zap.Error(err))
		return nil
	}

	reader := bytes.NewReader(buf)
	m := bpflib.NewModuleFromReader(reader)

	if err := m.Load(nil); err != nil {
		zap.L().Info("Failed to load BPF in kernel")
		if len(err.String()) < 256 {
			zap.L().Debug("BPF Load error:", zap.Error(err))
		}
		return nil
	}

	sfAppAck := m.SocketFilter("socket/app_ack")
	if sfAppAck == nil {
		zap.L().Info("Failed to load socket filter app_ack")
		return nil
	}

	if err := bpflib.PinObject(sfAppAck.Fd(), bpf.bpfPath); err != nil {
		zap.L().Info("Failed to pin bpf to file system", zap.Error(err))
		return nil
	}

	sessionMap := m.Map("sessions")
	if sessionMap == nil {
		zap.L().Info("Failed to load sessions map")
		return nil
	}

	bpf.m = m
	bpf.sessionMap = sessionMap

	return bpf
}

func (ebpf *ebpfModule) CreateFlow(tcpTuple *connection.TCPTuple) {
	var key flow
	var val uint8

	key.srcIP = binary.BigEndian.Uint32(tcpTuple.SourceAddress)
	key.dstIP = binary.BigEndian.Uint32(tcpTuple.DestinationAddress)
	key.srcPort = tcpTuple.SourcePort
	key.dstPort = tcpTuple.DestinationPort

	val = 1

	err := ebpf.m.UpdateElement(ebpf.sessionMap, unsafe.Pointer(&key), unsafe.Pointer(&val), 0)
	if err != nil {
		zap.L().Debug("Update bpf map failed",
			zap.String("packet", tcpTuple.String()),
			zap.Error(err))
	}
}

func (ebpf *ebpfModule) RemoveFlow(tcpTuple *connection.TCPTuple) {
	var key flow

	key.srcIP = binary.BigEndian.Uint32(tcpTuple.SourceAddress)
	key.dstIP = binary.BigEndian.Uint32(tcpTuple.DestinationAddress)
	key.srcPort = tcpTuple.SourcePort
	key.dstPort = tcpTuple.DestinationPort

	err := ebpf.m.DeleteElement(ebpf.sessionMap, unsafe.Pointer(&key))
	if err != nil {
		zap.L().Debug("Delete bpf map failed",
			zap.String("packet", tcpTuple.String()),
			zap.Error(err))
	}
}

func (ebpf *ebpfModule) GetBPFPath() string {
	return ebpf.bpfPath
}

func (ebpf *ebpfModule) Cleanup() {
	if err := os.Remove(ebpf.bpfPath); err != nil {
		zap.L().Error("Failed to remove bpf file during cleanup", zap.Error(err))
	}
}
