package extractors

import (
	"fmt"
)

type errNetclsAlreadyProgrammed struct {
	mark string
}

func (e *errNetclsAlreadyProgrammed) Error() string {
	return fmt.Sprintf("net_cls cgroup already programmed with mark %s", e.mark)
}

// ErrNetclsAlreadyProgrammed is returned from the NetclsProgrammer when the net_cls cgroup for this pod has already been programmed
func ErrNetclsAlreadyProgrammed(mark string) error {
	return &errNetclsAlreadyProgrammed{mark: mark}
}

// ErrNoHostNetworkPod is returned from the NetclsProgrammer if the given pod is not a host network pod.
var ErrNoHostNetworkPod = fmt.Errorf("pod is not a host network pod")

// IsErrNetclsAlreadyProgrammed checks if the provided error is an ErrNetclsAlreadyProgrammed error
func IsErrNetclsAlreadyProgrammed(err error) bool {
	switch err.(type) {
	case *errNetclsAlreadyProgrammed:
		return true
	default:
		return false
	}
}

// IsErrNoHostNetworkPod checks if the provided error is an ErrNoHostNetworkPod error
func IsErrNoHostNetworkPod(err error) bool {
	return err.Error() == ErrNoHostNetworkPod.Error()
}
