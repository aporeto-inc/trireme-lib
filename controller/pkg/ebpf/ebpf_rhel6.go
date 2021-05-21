// +build rhel6

package ebpf

import (
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
)

// BPFPath holds the BPF path
var BPFPath = "/sys/fs/bpf/app-ack"

type ebpfRhel6 struct {
}

// IsEBPFSupported returns false for RHEL6.
func IsEBPFSupported() bool {
	return false
}

// LoadBPF is not supported on RHEL6.
func LoadBPF() BPFModule {
	return nil
}

func (*ebpfRhel6) CreateFlow(*packet.Packet) {
}

func (*ebpfRhel6) RemoveFlow(*packet.Packet) {
}

func (*ebpfRhel6) Cleanup() {
}

func (*ebpfRhel6) GetBPFPath() string {
	return ""
}
