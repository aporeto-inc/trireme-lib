package policy

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDefaultLogPrefix(t *testing.T) {
	Convey("When I request a new default log prefix", t, func() {
		t := DefaultLogPrefix("abc")
		f := &FlowPolicy{
			Action: Reject,
		}
		So(t, ShouldEqual, "abc:default:default"+f.EncodedActionString())
	})
}
