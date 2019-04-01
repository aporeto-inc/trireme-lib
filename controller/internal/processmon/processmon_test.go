package processmon

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/pkg/env"
	"go.aporeto.io/trireme-lib/policy"
)

const (
	testDirBase = "/tmp"
)

func launchContainer(path string) int {

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

func killContainer() {

	killcmd := exec.Command("docker", "rm", "-f", "testprocessmon")
	killcmd.Run() // nolint: errcheck
}

func fakeExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestCmdHelper", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

func TestCmdHelper(t *testing.T) {

	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	os.Exit(0)
}

func TestLaunchProcess(t *testing.T) {

	Convey("Given a test setup for launch", t, func() {
		//Will use refPid to be 1 (init) guaranteed to be there
		//Normal case should launch a process

		refPid := 1
		dir, _ := os.Getwd()
		refNSPath := ""

		err := os.MkdirAll("/tmp/1/ns/net", os.ModePerm)
		So(err, ShouldBeNil)
		defer func() {
			os.RemoveAll("/tmp/1/ns/net") // nolint errcheck
		}()

		err = os.Chdir("testbinary")
		So(err, ShouldBeNil)
		defer os.Chdir(dir) // nolint

		buildCmd := fmt.Sprintf("GOOS=%s GOARCH=%s go build", runtime.GOOS, runtime.GOARCH)

		err = exec.Command("bash", "-c", buildCmd).Run()
		So(err, ShouldBeNil)

		err = exec.Command("cp", filepath.Join(dir, "testbinary/testbinary"), testDirBase).Run()
		So(err, ShouldBeNil)

		ctx, cancel := context.WithCancel(context.TODO())
		defer cancel()

		errChannel := make(chan *policy.RuntimeError)

		rpchdl := rpcwrapper.NewTestRPCClient()
		contextID := "pu1"

		pm := New(ctx, &env.RemoteParameters{}, errChannel, rpchdl)
		p, ok := pm.(*RemoteMonitor)
		So(ok, ShouldBeTrue)

		Convey("if the process is already activated, then it should return with initialize false and no error", func() {
			p.activeProcesses.AddOrUpdate(contextID, &processInfo{})

			initialize, err := p.LaunchRemoteEnforcer(contextID, refPid, refNSPath, "", "mysecret", testDirBase)
			So(err, ShouldBeNil)
			So(initialize, ShouldBeFalse)
		})

		Convey("if the process is not already activated and stat fails, it should error and cleanup", func() {
			initialize, err := p.LaunchRemoteEnforcer(contextID, refPid, "", "", "my secret", "/badpath")
			So(initialize, ShouldBeFalse)
			So(err, ShouldNotBeNil)

			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)

		})

		Convey("if the process is not already activated and pid stat fails, it should error and cleanup", func() {
			initialize, err := p.LaunchRemoteEnforcer(contextID, 10000, refNSPath, "", "my secret", "/badpath")
			So(initialize, ShouldBeFalse)
			So(err, ShouldNotBeNil)

			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)

		})

		Convey("if the process is not already activated and this is the host namespace, it should fail and cleanup", func() {
			rpchdl.MockGetRPCClient(t, func(string) (*rpcwrapper.RPCHdl, error) {
				return nil, nil
			})
			initialize, err := p.LaunchRemoteEnforcer(contextID, refPid, refNSPath, "", "my secret", testDirBase)
			So(initialize, ShouldBeFalse)
			So(err, ShouldNotBeNil)

			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)

		})

		Convey("if the process is not already activated and the namespace is there", func() {
			rpchdl.MockGetRPCClient(t, func(string) (*rpcwrapper.RPCHdl, error) {
				return nil, nil
			})
			pid := launchContainer(testDirBase)
			defer killContainer()

			execCommand = fakeExecCommand
			initialize, err := p.LaunchRemoteEnforcer(contextID, pid, refNSPath, "", "my secret", testDirBase)
			So(initialize, ShouldBeTrue)
			So(err, ShouldBeNil)

			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldBeNil)

		})

		close(errChannel)

	})
}

func Test_KillRemoteEnforcer(t *testing.T) {
	Convey("Given a test setup for kill ", t, func() {
		ctx, cancel := context.WithCancel(context.TODO())
		defer cancel()

		errChannel := make(chan *policy.RuntimeError)
		defer close(errChannel)

		rpchdl := rpcwrapper.NewTestRPCClient()
		contextID := "abcd"

		pm := New(ctx, &env.RemoteParameters{}, errChannel, rpchdl)
		p, ok := pm.(*RemoteMonitor)
		So(ok, ShouldBeTrue)

		Convey("if the process is not already activated, I should get an error", func() {
			err := p.KillRemoteEnforcer(contextID, false)
			So(err, ShouldNotBeNil)
		})

		Convey("if the process info is empty, it should error and should remove it from cache", func() {
			p.activeProcesses.AddOrUpdate(contextID, &processInfo{
				contextID: contextID,
			})

			err := p.KillRemoteEnforcer(contextID, false)
			So(err, ShouldNotBeNil)
			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)
		})

		Convey("if the RPC call succeeds, it should complete with no errors", func() {
			p.activeProcesses.AddOrUpdate(contextID, &processInfo{
				contextID: contextID,
				process:   &os.Process{},
			})

			rpchdl.MockRemoteCall(t, func(contextID string, name string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
				return nil
			})
			rpchdl.MockDestroyRPCClient(t, func(string) {
			})

			err := p.KillRemoteEnforcer(contextID, false)
			So(err, ShouldBeNil)
			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)
		})

		Convey("if the RPC call fails, it should complete with no errors after issuing a kill and its not force", func() {
			p.activeProcesses.AddOrUpdate(contextID, &processInfo{
				contextID: contextID,
				process:   &os.Process{},
			})

			rpchdl.MockRemoteCall(t, func(contextID string, name string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
				return fmt.Errorf("some error")
			})
			rpchdl.MockDestroyRPCClient(t, func(string) {
			})

			err := p.KillRemoteEnforcer(contextID, false)
			So(err, ShouldBeNil)
			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)
		})

		Convey("if the RPC call fails, it should complete with no errors after issuing a kill and  it is force", func() {
			p.activeProcesses.AddOrUpdate(contextID, &processInfo{
				contextID: contextID,
				process:   &os.Process{},
			})

			rpchdl.MockRemoteCall(t, func(contextID string, name string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
				return fmt.Errorf("some error")
			})
			rpchdl.MockDestroyRPCClient(t, func(string) {
			})

			err := p.KillRemoteEnforcer(contextID, false)
			So(err, ShouldBeNil)
			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)
		})

		Convey("if the RPC call timesout it should complete with no errors", func() {
			p.activeProcesses.AddOrUpdate(contextID, &processInfo{
				contextID: contextID,
				process:   &os.Process{},
			})

			rpchdl.MockRemoteCall(t, func(contextID string, name string, req *rpcwrapper.Request, resp *rpcwrapper.Response) error {
				time.Sleep(10 * time.Second)
				return fmt.Errorf("time-out-error")
			})
			rpchdl.MockDestroyRPCClient(t, func(string) {
			})

			err := p.KillRemoteEnforcer(contextID, false)
			So(err, ShouldBeNil)
			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)
		})
	})
}

func Test_CollectExitStatus(t *testing.T) {
	Convey("Given a test setup for kill ", t, func() {
		ctx, cancel := context.WithCancel(context.TODO())
		defer cancel()

		errChannel := make(chan *policy.RuntimeError)
		defer close(errChannel)

		rpchdl := rpcwrapper.NewTestRPCClient()
		contextID := "12345"

		pm := New(ctx, &env.RemoteParameters{}, errChannel, rpchdl)
		p, ok := pm.(*RemoteMonitor)
		So(ok, ShouldBeTrue)

		Convey("When I call collectExistStatus in the background, I should get the errors in the channel", func() {
			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()
			p.activeProcesses.AddOrUpdate(contextID, &processInfo{
				contextID: contextID,
				process:   &os.Process{},
			})

			go p.collectChildExitStatus(ctx)

			p.childExitStatus <- exitStatus{
				process:    1,
				contextID:  contextID,
				exitStatus: fmt.Errorf("process error"),
			}

			recievedError := <-errChannel

			So(recievedError, ShouldNotBeNil)
			So(recievedError.ContextID, ShouldResemble, contextID)
			So(recievedError.Error, ShouldNotBeNil)
			So(recievedError.Error.Error(), ShouldResemble, "remote enforcer terminated: process error")
			_, err := p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)
		})

	})
}
