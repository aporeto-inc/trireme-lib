// +build linux,!rhel6

package processmon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/env"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

const (
	testDirBase = "/tmp"
)

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

		err = exec.Command("cp", "-p", filepath.Join(dir, "testbinary/testbinary"), testDirBase).Run()
		So(err, ShouldBeNil)

		ctx, cancel := context.WithCancel(context.TODO())
		defer cancel()

		errChannel := make(chan *policy.RuntimeError)
		defer cleanupErrChannel(errChannel)

		rpchdl := rpcwrapper.NewTestRPCClient()
		contextID := "pu1"

		pm := New(ctx, &env.RemoteParameters{}, errChannel, rpchdl, 0)
		p, ok := pm.(*RemoteMonitor)
		So(ok, ShouldBeTrue)

		Convey("if the process is already activated, then it should return with initialize false and no error", func() {
			p.activeProcesses.AddOrUpdate(contextID, &processInfo{})

			initialize, err := p.LaunchRemoteEnforcer(contextID, refPid, refNSPath, "", "mysecret", testDirBase, policy.EnforcerMapping)
			So(err, ShouldBeNil)
			So(initialize, ShouldBeFalse)
		})

		Convey("if the process is not already activated and stat fails, it should error and cleanup", func() {
			initialize, err := p.LaunchRemoteEnforcer(contextID, refPid, "", "", "my secret", "/badpath", policy.EnforcerMapping)
			So(err, ShouldNotBeNil)
			So(initialize, ShouldBeFalse)

			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)

		})

		Convey("if the process is not already activated and pid stat fails, it should error and cleanup", func() {
			initialize, err := p.LaunchRemoteEnforcer(contextID, 10000, refNSPath, "", "my secret", "/badpath", policy.EnforcerMapping)
			So(err, ShouldNotBeNil)
			So(initialize, ShouldBeFalse)

			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldNotBeNil)

		})

		Convey("if the process is not already activated and this is the host namespace, it should fail and cleanup", func() {
			rpchdl.MockGetRPCClient(t, func(string) (*rpcwrapper.RPCHdl, error) {
				return nil, nil
			})
			initialize, err := p.LaunchRemoteEnforcer(contextID, refPid, refNSPath, "", "my secret", testDirBase, policy.EnforcerMapping)
			So(err, ShouldNotBeNil)
			So(initialize, ShouldBeFalse)

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
			initialize, err := p.LaunchRemoteEnforcer(contextID, pid, refNSPath, "", "my secret", testDirBase, policy.EnforcerMapping)
			So(err, ShouldBeNil)
			So(initialize, ShouldBeTrue)

			_, err = p.activeProcesses.Get(contextID)
			So(err, ShouldBeNil)

		})

	})

}
