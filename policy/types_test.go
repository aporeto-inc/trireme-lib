// +build !windows

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
		Convey("I should have the correct default prefix", func() {
			So(t, ShouldEqual, "1134309195:default:default:"+f.EncodedActionString())
		})
	})
}

func TestDefaultDroppedPacketLogPrefix(t *testing.T) {
	Convey("When I request a new default dropped log prefix", t, func() {
		t := DefaultDroppedPacketLogPrefix("abcasd")

		Convey("I should have the correct default prefix", func() {
			So(t, ShouldEqual, "2569040509:default:default:10")
		})
	})
}

func TestDefaultAcceptLogPrefix(t *testing.T) {
	Convey("When I request a new default dropped log prefix", t, func() {
		t := DefaultAcceptLogPrefix("abcasasd")

		Convey("I should have the correct default prefix", func() {
			So(t, ShouldEqual, "2899028581:default:default:3")
		})
	})
}

func TestLogPrefix(t *testing.T) {
	Convey("When I request log prefix reject", t, func() {
		f := &FlowPolicy{
			Action:        Reject,
			ObserveAction: ObserveNone,
			PolicyID:      "deadbeef",
			ServiceID:     "beaddead",
		}
		Convey("I should have the correct log prefix", func() {
			So(f.LogPrefix("somecontextID"), ShouldEqual, "3985287229:deadbeef:beaddead:6")
		})
	})

	Convey("When I request log prefix", t, func() {
		f := &FlowPolicy{
			Action:        Accept,
			ObserveAction: ObserveNone,
			PolicyID:      "deadbeef",
			ServiceID:     "beaddead",
		}
		Convey("I should have the correct log prefix", func() {
			So(f.LogPrefix("somecontextID"), ShouldEqual, "3985287229:deadbeef:beaddead:3")
		})
	})
}

func TestLogPrefixAction(t *testing.T) {
	Convey("When I request log prefix action 6", t, func() {
		f := &FlowPolicy{
			Action:        Accept,
			ObserveAction: ObserveNone,
			PolicyID:      "deadbeef",
			ServiceID:     "beaddead",
		}
		Convey("I should have the correct log prefix", func() {
			So(f.LogPrefixAction("somecontextID", "6"), ShouldEqual, "3985287229:deadbeef:beaddead:6")
		})
	})

	Convey("When I request log prefix action 0", t, func() {
		f := &FlowPolicy{
			Action:        Accept,
			ObserveAction: ObserveNone,
			PolicyID:      "deadbeef",
			ServiceID:     "beaddead",
		}
		Convey("I should have the correct log prefix", func() {
			So(f.LogPrefixAction("somecontextID", "0"), ShouldEqual, "3985287229:deadbeef:beaddead:6")
		})
	})

	Convey("When I request log prefix action empty", t, func() {
		f := &FlowPolicy{
			Action:        Accept,
			ObserveAction: ObserveNone,
			PolicyID:      "deadbeef",
			ServiceID:     "beaddead",
		}
		Convey("I should have the correct log prefix", func() {
			So(f.LogPrefixAction("somecontextID", ""), ShouldEqual, "3985287229:deadbeef:beaddead:6")
		})
	})
}

func TestFnv32(t *testing.T) {

	Convey("When I request log prefix with no data", t, func() {
		hash, err := Fnv32Hash()

		Convey("I should have the hash", func() {
			So(hash, ShouldBeEmpty)
			So(err, ShouldNotBeNil)
		})
	})

	Convey("When I request log prefix with small data", t, func() {
		hash, err := Fnv32Hash("xyz")

		Convey("I should have the hash", func() {
			So(hash, ShouldEqual, "845396910")
			So(err, ShouldBeNil)
		})
	})

	Convey("When I request log prefix with large data", t, func() {
		hash, err := Fnv32Hash("xyzsadsadasfkjhjkasdjhsajkdhsad", "asdasdasda", "asdhjkashdjkashdjashdkasjdhasjkdhjashdkasjdhkaslfjsalkjdklasjdklasjdk")

		Convey("I should have the hash", func() {
			So(hash, ShouldEqual, "2149035768")
			So(err, ShouldBeNil)
		})
	})
}

func TestEncodedStringToActionInvalidValue(t *testing.T) {
	Convey("When I run decode and encode, the results should match", t, func() {
		ea := "badvalue"
		_, _, err := EncodedStringToAction(ea)
		if err == nil {
			Convey("I should get an error for value "+ea, func() {
				So(err, ShouldNotBeNil)
			})
		}
	})
}

func TestEncodeDecodePrefix(t *testing.T) {
	Convey("When I run decode and encode, the results should match", t, func() {
		encodedAction := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}
		for _, ea := range encodedAction {
			f := &FlowPolicy{}
			var err error
			f.Action, f.ObserveAction, err = EncodedStringToAction(ea)
			Convey("I should have the same actions after decoding and encoding for action "+ea, func() {
				So(err, ShouldBeNil)
				So(f.EncodedActionString(), ShouldEqual, ea)
			})
		}
	})
}
