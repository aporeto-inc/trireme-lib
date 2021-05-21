package cri

// Type is the type to be given at startup
type Type string

// Different enforcer types
const (
	TypeNone       Type = "none"       // TypeNone is the default enforcer type
	TypeDocker     Type = "docker"     // TypeDocker is enforcerd which uses CRI docker
	TypeCRIO       Type = "crio"       // TypeDaemonset is enforcerd which uses CRIO CRI
	TypeContainerD Type = "containerd" // TypeContainerD is a enforcerd which uses containerD CRI
)

// Container returns true iff the enforcer supports containers
func (d Type) Container() bool {
	return d.Docker() || d.CRIO() || d.ContainerD()
}

// CRIO returns true if the enforcer is using CRI for container management
func (d Type) CRIO() bool {
	return d == TypeCRIO
}

// Docker returns true if the enforcer supports docker
func (d Type) Docker() bool {
	return d == TypeDocker
}

// ContainerD returns true if enforcerd is using ContainerD CRI
func (d Type) ContainerD() bool {
	return d == TypeContainerD
}

// SupportRuncProxy returns true iff the enforcer supports runc proxy
func (d Type) SupportRuncProxy() bool {
	return d.Docker() || d.CRIO() || d.ContainerD()
}
