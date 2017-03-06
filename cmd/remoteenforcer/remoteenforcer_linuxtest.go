// +build linux !darwin

package remoteenforcer

import (
	"os"
	"testing"

	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	. "github.com/smartystreets/goconvey/convey"
)

func TestInitEnforcer(t *testing.T) {
	server := NewServer(nil, "/tmp/rpc.sock", "MySecret")
	Convey("When InitEnforcer is called", t, func() {
		Convey("When we failed to switch network namepsace", func() {
			os.Setenv("NSENTER_ERROR_STATE", "ERROR")
			req := rpcwrapper.Request{}
			resp := &rpcwrapper.Response{}
			err := server.InitEnforcer(req, resp)
			So(err, ShouldNotBeNil)
			os.Setenv("NSENTER_ERROR_STATE", "")

		})
	})
}
