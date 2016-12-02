package ProcessMon

import (
	"os"
	"testing"
)

func TestLaunchProcess(t *testing.T) {
	//Will use refPid to be 1 (init) guaranteed to be there
	//Normal case should launch a process
	contextID := 12345
	refPid := 1
	err := LaunchProcess(contextID, refPid)
	if err != nil {
		t.Error("Launch Process Fails to launch a process")
	}
	//Trying to launch in the same context should suceed
	err = LaunchProcess(contextID, refPid)
	if err != nil {
		t.Error("Launch Process Fails to launch a process")
	}
	KillProcess(contextID)
	//Launch Process Should not fail if the /var/run/netns does not exist
	os.Remove("/var/run/netns")
	err = LaunchProcess(contextID, refPid)
	if err != nil {
		t.Errorf("Failed when the directory is missing %v", err)
	}
	KillProcess(contextID)
	os.Rename("/opt/trireme/enforcer", "/opt/trireme/enforcer.orig")
	//if binary  is absent we should return an error
	err = LaunchProcess(contextID, refPid)
	if err == nil {
	}

}
func TestGetExitStatus(t *testing.T) {

}
