// +build !windows

package connection

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/pucontext"
)

func Test_NewConnection(t *testing.T) {

	Convey("Given I create a new connection with packet nil", t, func() {
		conn := NewTCPConnection(&pucontext.PUContext{}, nil)
		So(conn, ShouldNotBeNil)
	})

	Convey("Given I create a new connection with packet", t, func() {
		conn := NewTCPConnection(&pucontext.PUContext{}, &packet.Packet{})
		So(conn, ShouldNotBeNil)
	})
}
