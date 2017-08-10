package processmon

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
)

func LaunchContainer() int {
	var out, out2 bytes.Buffer
	runcmd := exec.Command("docker", "run", "-d", "--name=testprocessmon", "nginx")
	runcmd.Stdout = &out
	runcmd.Run() // nolint: errcheck
	runcmd1 := exec.Command("docker", "inspect", "testprocessmon")
	runcmd1.Stdout = &out2
	runcmd1.Run() // nolint: errcheck
	reader := bytes.NewReader(out2.Bytes())
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "Pid") {
			a := strings.Split(scanner.Text(), ":")[1]
			pid, _ := strconv.Atoi(strings.TrimSpace(a[:len(a)-1]))
			fmt.Println(pid)
			return pid
		}
	}
	return 0
}
func KillContainer() {
	killcmd := exec.Command("docker", "rm", "-f", "testprocessmon")
	killcmd.Run() // nolint: errcheck
}
func TestLaunchProcess(t *testing.T) {
	//Will use refPid to be 1 (init) guaranteed to be there
	//Normal case should launch a process
	rpchdl := rpcwrapper.NewTestRPCClient()
	p := newProcessMon()
	contextID := "12345"

	refPid := 1
	refNSPath := ""
	dir, _ := os.Getwd()
	p.SetnsNetPath("/tmp/")
	err := p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", "/proc")
	if err != nil {
		t.Errorf("TEST:Launch Process launches a process in the hostnamespace %v -- %s", err, dir)
		t.SkipNow()
	}

	refPid = LaunchContainer()
	dir, _ = os.Getwd()
	p.SetnsNetPath("/tmp/")
	err = p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", "/proc")
	if err != nil {
		t.Errorf("TEST:Launch Process Fails to launch a process %v -- %s", err, dir)
		t.SkipNow()
	}
	//Trying to launch in the same context should succeed
	err = p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", "/proc")
	if err != nil {
		t.Errorf("TEST:Launch Process Fails to launch a process")
	}
	//Cleanup
	rpchdl.MockRemoteCall(t, func(passed_contextID string, methodName string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
		return errors.New("Null Error")
	})
	p.KillProcess(contextID)
	//Launch Process Should not fail if the /var/run/netns does not exist
	os.Remove("/var/run/netns") // nolint
	err = p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", "/proc")
	if err != nil {
		t.Errorf("TEST:Failed when the directory is missing %v", err)
	}
	p.KillProcess(contextID)

	os.Rename("./remote_enforcer.orig", "./remote_enforcer") //nolint
	rpchdl.MockNewRPCClient(t, func(contextID string, channel string, secret string) error {
		return nil
	})
	err = p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", "/proc")
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
	KillContainer()
}

func TestGetExitStatus(t *testing.T) {
	contextID := "12345"
	refPid := LaunchContainer()
	refNSPath := ""
	//Lets launch process
	p := newProcessMon()
	p.SetnsNetPath("/tmp/")
	rpchdl := rpcwrapper.NewTestRPCClient()
	err := p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", "/proc")
	if err != nil {
		t.Errorf("TEST:Launch Process Fails to launch a process")
	}
	if p.GetExitStatus(contextID) {
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
	KillContainer()
}

func TestSetExitStatus(t *testing.T) {
	contextID := "12345"
	refPid := LaunchContainer()
	refNSPath := ""
	//Lets launch process
	p := newProcessMon()
	p.SetnsNetPath("/tmp/")
	//Error returned when process does not exists
	err := p.SetExitStatus(contextID, true)
	if err == nil {
		t.Errorf("TEST:Exit status succeeds  when process does not exist")
	}
	rpchdl := rpcwrapper.NewTestRPCClient()
	rpchdl.MockNewRPCClient(t, func(contextID string, channel string, secret string) error {
		return nil
	})
	err = p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", "/proc")
	if err != nil {
		t.Errorf("TEST: Failed to launch process")
	}
	err = p.SetExitStatus(contextID, true)
	if err != nil {
		t.Errorf("TEST:Exit status failed for enforcer process")
	}
	if !p.GetExitStatus(contextID) {
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
	KillContainer()
}

func TestKillProcess(t *testing.T) {
	contextID := "12345"
	refPid := LaunchContainer()
	refNSPath := ""
	calledRemoteCall := false
	// paramvalidate := false

	//Lets launch process
	p := newProcessMon()
	p.SetnsNetPath("/tmp/")
	rpchdl := rpcwrapper.NewTestRPCClient()
	//Kill Process should return an error when we try to kill non-existing process
	p.KillProcess(contextID)

	if err := p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", "/proc"); err != nil {
		t.Errorf("Failed to launch process  %s", err.Error())
	}
	rpchdl.MockRemoteCall(t, func(passed_contextID string, methodName string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
		calledRemoteCall = true
		return errors.New("Null Error")
	})
	p.KillProcess(contextID)
	if !calledRemoteCall {
		t.Errorf("TEST:RPC call not executed")
	}
	KillContainer()
}

func TestGetProcessManagerHdl(t *testing.T) {
	hdl := GetProcessManagerHdl()
	cache := cache.NewCache()

	if !reflect.DeepEqual(hdl.(*ProcessMon).activeProcesses, cache) {
		t.Errorf("ProcessManagerhandle don't match with cache")
	}
}
