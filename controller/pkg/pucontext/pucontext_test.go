package pucontext

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

func Test_NewPU(t *testing.T) {

	Convey("When I call NewPU with proper data", t, func() {

		fp := &policy.PUInfo{
			Runtime: policy.NewPURuntimeWithDefaults(),
			Policy:  policy.NewPUPolicyWithDefaults(),
		}

		pu, err := NewPU("pu1", fp, 24*time.Hour)

		Convey("I should not get error", func() {
			So(pu, ShouldNotBeNil)
			So(pu.HashID(), ShouldEqual, pu.hashID)
			So(pu.Counters(), ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})
}

func Test_PUSearch(t *testing.T) {

	Convey("When I call PU Search", t, func() {

		portRange80, _ := portspec.NewPortSpec(80, 85, nil)
		portRange90, _ := portspec.NewPortSpec(90, 100, nil)

		tagSelectorList := policy.TagSelectorList{
			policy.TagSelector{
				Clause: []policy.KeyValueOperator{
					{
						Key:      "app",
						Value:    []string{"web"},
						ID:       "asfasfasdasd",
						Operator: policy.Equal,
					},
					{
						Key:       "@sys:port",
						Value:     []string{"TCP"},
						ID:        "",
						Operator:  policy.Equal,
						PortRange: portRange80,
					},
				},
				Policy: &policy.FlowPolicy{
					PolicyID: "2",
					Action:   policy.Accept,
				},
			},
			policy.TagSelector{
				Clause: []policy.KeyValueOperator{
					{
						Key:      "app",
						Value:    []string{"web"},
						ID:       "asfasfasdasd",
						Operator: policy.Equal,
					},
					{
						Key:       "@sys:port",
						Value:     []string{"TCP"},
						ID:        "",
						Operator:  policy.Equal,
						PortRange: portRange90,
					},
				},
				Policy: &policy.FlowPolicy{
					PolicyID: "2",
					Action:   policy.Accept,
				},
			},
		}

		d := policy.NewPUPolicy(
			"id",
			"/abc",
			policy.AllowAll,
			nil,
			nil,
			nil,
			nil,
			tagSelectorList,
			nil,
			nil,
			nil,
			nil,
			0,
			0,
			nil,
			nil,
			[]string{},
			policy.EnforcerMapping,
		)

		fp := &policy.PUInfo{
			Runtime: policy.NewPURuntimeWithDefaults(),
			Policy:  d,
		}

		pu, _ := NewPU("pu1", fp, 24*time.Hour)

		tags := policy.NewTagStore()
		tags.AppendKeyValue("app", "web")
		tags.AppendKeyValue(constants.PortNumberLabelString, "TCP/85")

		report, flow := pu.SearchRcvRules(tags)

		Convey("The action should be Accept when port is 85", func() {
			So(flow, ShouldNotBeNil)
			So(report, ShouldNotBeNil)
			So(flow.Action, ShouldEqual, policy.Accept)
			So(report.Action, ShouldEqual, policy.Accept)
			So(flow, ShouldNotBeNil)
		})

		tags = policy.NewTagStore()
		tags.AppendKeyValue("app", "web")
		tags.AppendKeyValue(constants.PortNumberLabelString, "TCP/98")

		report, flow = pu.SearchRcvRules(tags)

		Convey("The action should be Accept when port is 98", func() {
			So(flow, ShouldNotBeNil)
			So(report, ShouldNotBeNil)
			So(flow.Action, ShouldEqual, policy.Accept)
			So(report.Action, ShouldEqual, policy.Accept)
			So(flow, ShouldNotBeNil)
		})

		tags = policy.NewTagStore()
		tags.AppendKeyValue("app", "web")
		tags.AppendKeyValue(constants.PortNumberLabelString, "TCP/101")

		report, flow = pu.SearchRcvRules(tags)

		Convey("The action should be Reject when port is 101", func() {
			So(flow, ShouldNotBeNil)
			So(report, ShouldNotBeNil)
			So(flow.Action, ShouldEqual, policy.Reject)
			So(report.Action, ShouldEqual, policy.Reject)
			So(flow, ShouldNotBeNil)
		})

	})
}
