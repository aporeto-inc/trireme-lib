package processmon

import (
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
)

func TestLaunchProcess(t *testing.T) {
	//Will use refPid to be 1 (init) guaranteed to be there
	//Normal case should launch a process
	rpchdl := rpcwrapper.NewTestRPCClient()
	p := newProcessMon()
	contextID := "12345"
	refPid := 1
	dir, _ := os.Getwd()
	p.SetnsNetPath("/tmp/")
	setprocessname("cat") // Cat will block and should be present on all linux
	err := p.LaunchProcess(contextID, refPid, rpchdl, "")
	if err != nil {
		t.Errorf("TEST:Launch Process Fails to launch a process %v -- %s", err, dir)
		t.SkipNow()
	}
	//Trying to launch in the same context should suceed
	err = p.LaunchProcess(contextID, refPid, rpchdl, "")
	if err != nil {
		t.Errorf("TEST:Launch Process Fails to launch a process")
	}
	//Cleanup
	rpchdl.MockRemoteCall(t, func(passed_contextID string, methodName string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
		return errors.New("Null Error")
	})
	p.KillProcess(contextID)
	//Launch Process Should not fail if the /var/run/netns does not exist
	os.Remove("/var/run/netns")
	err = p.LaunchProcess(contextID, refPid, rpchdl, "")
	if err != nil {
		t.Errorf("TEST:Failed when the directory is missing %v", err)
	}
	p.KillProcess(contextID)

	os.Rename("./remote_enforcer.orig", "./remote_enforcer")
	rpchdl.MockNewRPCClient(t, func(contextID string, channel string) error {
		return nil
	})
	setprocessname("cat")
	err = p.LaunchProcess(contextID, refPid, rpchdl, "")
	if err != nil {
		t.Errorf("TEST:Failed to create RPC client %v", err)
	}
	//Cleanup
	p.KillProcess(contextID)
	//Did we clean all resources when we exited
	_, err = os.Stat("/tmp/" + strconv.Itoa(refPid) + ".sock")
	if err == nil {
		t.Errorf("TEST:Channel resource leaked ")
	}
	_, err = os.Stat("/var/run/netns/" + contextID)
	if err == nil {
		t.Errorf("TEST:Netns resource leaked ")
	}
}

func TestGetExitStatus(t *testing.T) {
	contextID := "12345"
	refPid := 1
	//Lets launch process
	p := newProcessMon()
	p.SetnsNetPath("/tmp/")
	setprocessname("cat")
	rpchdl := rpcwrapper.NewTestRPCClient()
	err := p.LaunchProcess(contextID, refPid, rpchdl, "")
	if err != nil {
		t.Errorf("TEST:Launch Process Fails to launch a process")
	}
	if p.GetExitStatus(contextID) != false {
		t.Errorf("TEST:Process delete status not intialized or getexitstatus returned wrong val")
	}
	rpchdl.MockRemoteCall(t, func(passed_contextID string, methodName string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
		return errors.New("Null Error")
	})
	p.KillProcess(contextID)
	//Did we clean all resources when we exited
	_, err = os.Stat("/tmp/" + strconv.Itoa(refPid) + ".sock")
	if err == nil {
		t.Errorf("TEST:Channel resource leaked ")
	}
	_, err = os.Stat("/var/run/netns/" + contextID)
	if err == nil {
		t.Errorf("TEST:Netns resource leaked ")
	}
}

func TestSetExitStatus(t *testing.T) {
	contextID := "12345"
	refPid := 1
	//Lets launch process
	p := newProcessMon()
	p.SetnsNetPath("/tmp/")
	setprocessname("cat")
	//Error returned when process does not exists
	err := p.SetExitStatus(contextID, true)
	if err == nil {
		t.Errorf("TEST:Exit status suceeds when process does not exist")
	}
	rpchdl := rpcwrapper.NewTestRPCClient()
	rpchdl.MockNewRPCClient(t, func(contextID string, channel string) error {
		return nil
	})
	err = p.LaunchProcess(contextID, refPid, rpchdl, "")
	err = p.SetExitStatus(contextID, true)
	if err != nil {
		t.Errorf("TEST:Exit status failed for enforcer process")
	}
	if p.GetExitStatus(contextID) != true {
		t.Errorf("TEST:SetExit Status failed")
	}
	rpchdl.MockRemoteCall(t, func(passed_contextID string, methodName string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
		return errors.New("Null Error")
	})
	p.KillProcess(contextID)
	//Did we clean all resources when we exited
	_, err = os.Stat("/tmp/" + strconv.Itoa(refPid) + ".sock")
	if err == nil {
		t.Errorf("TEST:Channel resource leaked ")
	}
	_, err = os.Stat("/var/run/netns/" + contextID)
	if err == nil {
		t.Errorf("TEST:Netns resource leaked ")
	}

}

func TestKillProcess(t *testing.T) {
	contextID := "12345"
	refPid := 1
	calledRemoteCall := false
	// paramvalidate := false

	//Lets launch process
	p := newProcessMon()
	p.SetnsNetPath("/tmp/")
	setprocessname("cat")
	rpchdl := rpcwrapper.NewTestRPCClient()
	//Kill Process should return an error when we try to kill non-existing process
	p.KillProcess(contextID)

	p.LaunchProcess(contextID, refPid, rpchdl, "")
	rpchdl.MockRemoteCall(t, func(passed_contextID string, methodName string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
		if contextID == passed_contextID {
			// paramvalidate = true
		}
		calledRemoteCall = true
		return errors.New("Null Error")
	})
	p.KillProcess(contextID)
	if calledRemoteCall != true {
		t.Errorf("TEST:RPC call not executed")
	}

}
