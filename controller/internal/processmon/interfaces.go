package processmon

import (
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// ProcessManager interface exposes methods implemented by a processmon
type ProcessManager interface {
	KillRemoteEnforcer(contextID string, force bool) error
	LaunchRemoteEnforcer(contextID string, refPid int, refNsPath string, arg string, statssecret string, procMountPoint string, enforcerType policy.EnforcerType) (bool, error)
}
