// +build darwin

package ebpf

import (
	"go.aporeto.io/trireme-lib/v11/controller/pkg/packet"
)

var BPFPath = "/sys/fs/bpf/app-ack"

type ebpfDarwin struct {
}

func ISeBPFSupported() bool {
	return false
}

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
