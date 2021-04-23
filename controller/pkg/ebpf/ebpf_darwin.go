// +build darwin

package ebpf

import (
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
)

// BPFPath holds the BPF path
var BPFPath = "/sys/fs/bpf/app-ack"

type ebpfDarwin struct {
}

// IsEBPFSupported returns false for Darwin.
func IsEBPFSupported() bool {
	return false
}

// LoadBPF is not supported on Darwin.
func LoadBPF() BPFModule {
	return nil
}

func (*ebpfDarwin) CreateFlow(*packet.Packet) {
}

func (*ebpfDarwin) RemoveFlow(*packet.Packet) {
}

func (*ebpfDarwin) Cleanup() {
}

func (*ebpfDarwin) GetBPFPath() string {
	return ""
}
