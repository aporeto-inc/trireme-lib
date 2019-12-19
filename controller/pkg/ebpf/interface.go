package ebpf

import "go.aporeto.io/trireme-lib/controller/pkg/connection"

type BPFModule interface {
	GetBPFPath() string
	CreateFlow(*connection.TCPTuple)
	RemoveFlow(*connection.TCPTuple)
	Cleanup()
}
