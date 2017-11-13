package processmon

import "github.com/aporeto-inc/trireme/internal/processmon"

// SetupCommandArgs sets up arguments to be passed to the remote trireme instances
func SetupCommandArgs(logToConsole bool, subProcessArgs []string) {

	h := processmon.GetProcessManagerHdl()
	if h == nil {
		panic("Unable to find process manager handle")
	}
	h.SetupLogAndProcessArgs(logToConsole, subProcessArgs)
}
