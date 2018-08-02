package policy

import (
	"reflect"
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
			So(t, ShouldEqual, "abc:default:default"+f.EncodedActionString())
		})
	})
}

func TestLogPrefix(t *testing.T) {
	Convey("When I request log prefix", t, func() {
		f := &FlowPolicy{
			Action:        Reject,
			ObserveAction: ObserveNone,
			PolicyID:      "deadbeef",
			ServiceID:     "beaddead",
		}
		Convey("I should have the correct log prefix", func() {
			So(f.LogPrefix("somecontext"), ShouldEqual, "somecontext:deadbeef:beaddead"+f.EncodedActionString())
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

func TestClone(t *testing.T) {
	type args struct {
		proto string
	}
	tests := []struct {
		name string
		l    IPRuleList
		args args
		want IPRuleList
	}{
		{
			name: "Test Cloning a TCP IP rules",
			l: IPRuleList{
				IPRule{
					Policy: &FlowPolicy{
						Action:   Accept,
						PolicyID: "2",
					},
					Address:  "20.0.0.0/8",
					Protocol: "tcp",
					Port:     "80",
				},
			},
			args: args{
				proto: "tcp",
			},
			want: IPRuleList{
				IPRule{
					Policy: &FlowPolicy{
						Action:   Accept,
						PolicyID: "2",
					},
					Address:  "20.0.0.0/8",
					Protocol: "tcp",
					Port:     "80",
				},
			},
		},
		{
			name: "Test Cloning a udp IP rules",
			l: IPRuleList{
				IPRule{
					Policy: &FlowPolicy{
						Action:   Accept,
						PolicyID: "2",
					},
					Address:  "20.0.0.0/8",
					Protocol: "udp",
					Port:     "80",
				},
			},
			args: args{
				proto: "udp",
			},
			want: IPRuleList{
				IPRule{
					Policy: &FlowPolicy{
						Action:   Accept,
						PolicyID: "2",
					},
					Address:  "20.0.0.0/8",
					Protocol: "udp",
					Port:     "80",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.l.Clone(tt.args.proto); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IPRuleList.Clone() = %v, want %v", got, tt.want)
			}
		})
	}
}
