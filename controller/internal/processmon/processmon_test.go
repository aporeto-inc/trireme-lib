package processmon

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/utils/cache"
)

const (
	testDirBase = "/tmp"
	testBinary  = "testbinary"
)

func LaunchContainer(path string) int {

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
			if err := os.MkdirAll(filepath.Join(path, fmt.Sprintf("%d/ns/net", pid)), os.ModePerm); err != nil {
				return 0
			}
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
	p := newProcessMon(testDirBase, testDirBase, testBinary)
	contextID := "12345"

	refPid := 1
	dir, _ := os.Getwd()
	refNSPath := ""

	if err := os.MkdirAll("/tmp/1/ns/net", os.ModePerm); err != nil {
		t.Errorf("TEST:Setup failed")
		t.SkipNow()
	}

	if err := os.Chdir("testbinary"); err != nil {
		t.Errorf("TEST:Setup failed")
		t.SkipNow()
	}
	defer os.Chdir(dir) // nolint

	buildCmd := fmt.Sprintf("GOOS=%s GOARCH=%s go build", runtime.GOOS, runtime.GOARCH)

	err := exec.Command("bash", "-c", buildCmd).Run()
	if err != nil {
		t.Errorf("TEST:Setup failed")
		t.SkipNow()
	}

	err = exec.Command("cp", filepath.Join(dir, "testbinary/testbinary"), testDirBase).Run()
	if err != nil {
		t.Errorf("TEST:Setup failed")
		t.SkipNow()
	}

	_, err = p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", testDirBase)
	if err == nil {
		t.Errorf("TEST:Launch Process launches a process in the hostnamespace -- %s should fail", dir)
		t.SkipNow()
	}

	refPid = LaunchContainer(testDirBase)
	dir, _ = os.Getwd()
	_, err = p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", testDirBase)
	if err != nil {
		t.Errorf("TEST:Launch Process Fails to launch a process %v -- %s", err, dir)
		t.SkipNow()
	}
	//Trying to launch in the same context should succeed
	_, err = p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", testDirBase)
	if err != nil {
		t.Errorf("TEST:Launch Process Fails to launch a process")
	}
	//Cleanup
	rpchdl.MockRemoteCall(t, func(passed_contextID string, methodName string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
		return errors.New("null error")
	})
	p.KillProcess(contextID)
	//Launch Process Should not fail if the /var/run/netns does not exist
	os.Remove("/var/run/netns") // nolint
	_, err = p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", testDirBase)
	if err != nil {
		t.Errorf("TEST:Failed when the directory is missing %v", err)
	}
	p.KillProcess(contextID)

	os.Rename("./remote_enforcer.orig", "./remote_enforcer") //nolint
	rpchdl.MockNewRPCClient(t, func(contextID string, channel string, secret string) error {
		return nil
	})
	_, err = p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", testDirBase)
	if err != nil {
		t.Errorf("TEST:Failed to create RPC client %v", err)
	}
	//Cleanup
	p.KillProcess(contextID)
	//Did we clean all resources when we exited
	_, err = os.Stat(filepath.Join(testDirBase, strconv.Itoa(refPid)+".sock"))
	if err == nil {
		t.Errorf("TEST:Channel resource leaked ")
	}
	_, err = os.Stat(filepath.Join("/var/run/netns", contextID))
	if err == nil {
		t.Errorf("TEST:Netns resource leaked ")
	}
	KillContainer()
}

func TestKillProcess(t *testing.T) {

	contextID := "12346"
	refPid := LaunchContainer(testDirBase)
	refNSPath := ""
	calledRemoteCall := false
	// paramvalidate := false

	//Lets launch process
	p := newProcessMon(testDirBase, testDirBase, testBinary)
	rpchdl := rpcwrapper.NewTestRPCClient()
	//Kill Process should return an error when we try to kill non-existing process
	p.KillProcess(contextID)

	if _, err := p.LaunchProcess(contextID, refPid, refNSPath, rpchdl, "", "mysecret", testDirBase); err != nil {
		t.Errorf("Failed to launch process  %s", err.Error())
	}
	rpchdl.MockRemoteCall(t, func(passed_contextID string, methodName string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
		calledRemoteCall = true
		return errors.New("null error")
	})
	p.KillProcess(contextID)
	if !calledRemoteCall {
		t.Errorf("TEST:RPC call not executed")
	}
	KillContainer()
}

func TestGetProcessManagerHdl(t *testing.T) {

	newProcessMon(netNSPath, remoteEnforcerTempBuildPath, remoteEnforcerBuildName)
	hdl := GetProcessManagerHdl()
	cache := cache.NewCache(processMonitorCacheName)

	if !reflect.DeepEqual(hdl.(*processMon).activeProcesses, cache) {
		t.Errorf("ProcessManagerhandle don't match with cache")
	}
}
