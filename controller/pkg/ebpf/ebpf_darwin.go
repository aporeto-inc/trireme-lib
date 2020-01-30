// +build darwin

package ebpf

import (
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
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

func (*ebpfRhel6) CreateFlow(*packet.Packet) {
}

func (*ebpfRhel6) RemoveFlow(*packet.Packet) {
}

func (*ebpfRhel6) Cleanup() {
}

func (*ebpfRhel6) GetBPFPath() string {
	return ""
}
