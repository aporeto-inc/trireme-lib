// +build !windows

package processmon

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/env"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
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

// cleanup and close the errChannel properly to prevent data race
func cleanupErrChannel(errChannel chan *policy.RuntimeError) {
forLoop:
	for {
		select {
		case <-errChannel:
			break forLoop
		case <-time.After(2 * time.Second):
			break forLoop
		}
	}
	close(errChannel)
}

func TestCmdHelper(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	os.Exit(0)
}

func Test_KillRemoteEnforcer(t *testing.T) {
	Convey("Given a test setup for kill ", t, func() {
		ctx, cancel := context.WithCancel(context.TODO())
		defer cancel()

		errChannel := make(chan *policy.RuntimeError)
		defer cleanupErrChannel(errChannel)

		rpchdl := rpcwrapper.NewTestRPCClient()
		contextID := "abcd"

		pm := New(ctx, &env.RemoteParameters{}, errChannel, rpchdl, 0)
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
		defer cleanupErrChannel(errChannel)

		rand.Seed(time.Now().UnixNano())

		rpchdl := rpcwrapper.NewTestRPCClient()
		pid := rand.Intn(299999) + 1
		contextID := strconv.Itoa(rand.Intn(1000000000) + 1)

		pm := New(ctx, &env.RemoteParameters{}, errChannel, rpchdl, 0)
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
				pid:        pid,
				contextID:  contextID,
				exitStatus: fmt.Errorf("process error"),
			}

			recievedError := <-errChannel

			So(recievedError, ShouldNotBeNil)
			So(recievedError.ContextID, ShouldEqual, contextID)
			So(recievedError.Error, ShouldNotBeNil)
			So(recievedError.Error.Error(), ShouldResemble, "remote enforcer terminated: childPid: "+strconv.Itoa(pid)+", contextID: "+contextID+", exitStatus: process error")
			_, err := p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)
		})

	})
}
