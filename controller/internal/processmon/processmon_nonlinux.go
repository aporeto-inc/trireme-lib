// +build windows darwin

package processmon

type process struct {

}

// KillProcess  unimplemented implement per platform
func (p *process) KillProcess(contextID string) {
	return
}

// LaunchProcess unimplemented implement per platform to launch a new copy of the process  
LaunchProcess(contextID string, refPid int, refNsPath string, rpchdl rpcwrapper.RPCClient, arg string, statssecret string, procMountPoint string) error {
		return nil
}

// SetLogParameters unimplemented pass log parameters for the launched process 
SetLogParameters(logToConsole, logWithID bool, logLevel string, logFormat string, compressedTags bool) {
	return
}