package processmon

import (
	"go.aporeto.io/trireme-lib/v11/policy"
)

// ProcessManager interface exposes methods implemented by a processmon
type ProcessManager interface {
	KillRemoteEnforcer(contextID string, force bool) error
	LaunchRemoteEnforcer(contextID string, refPid int, refNsPath string, arg string, statssecret string, procMountPoint string, enforcerType policy.EnforcerType) (bool, error)
}
