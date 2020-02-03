package ebpf

import "go.aporeto.io/trireme-lib/v11/controller/pkg/connection"

//BPFModule interface exposes the functionality to datapath
type BPFModule interface {
	GetBPFPath() string
	CreateFlow(*connection.TCPTuple)
	RemoveFlow(*connection.TCPTuple)
	Cleanup()
}
