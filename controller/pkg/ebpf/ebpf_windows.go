// +build windows

package ebpf

import (
	"go.aporeto.io/trireme-lib/v11/controller/pkg/packet"
)

var BPFPath = "/sys/fs/bpf/app-ack"

type ebpfRhel6 struct {
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
