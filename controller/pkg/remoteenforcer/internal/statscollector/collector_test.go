package statscollector

import (
	"testing"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/policy"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNewCollector(t *testing.T) {
	Convey("When I create a new collector", t, func() {
		c := NewCollector()
		Convey("The collector should not be nil ", func() {
			So(c, ShouldNotBeNil)
			So(c.GetAllRecords(), ShouldBeNil)
		})
	})
}

func TestCollectFlowEvent(t *testing.T) {
	Convey("Given a stats collector", t, func() {
		c := &collectorImpl{
			Flows: map[string]*collector.FlowRecord{},
		}

		Convey("When I add a flow event", func() {
			r := &collector.FlowRecord{
				ContextID:   "1",
				Source:      collector.NewEndPoint(collector.EnpointTypePU, "A", collector.OptionEndPointIPPort("1.1.1.1", 0)),
				Destination: collector.NewEndPoint(collector.EnpointTypePU, "B", collector.OptionEndPointIPPort("2.2.2.2", 0)),
				Count:       0,
				Tags:        policy.NewTagStore(),
				L4Protocol:  packet.IPProtocolTCP,
			}
			c.CollectFlowEvent(r)

			Convey("The flow should be in the cache", func() {
				So(len(c.Flows), ShouldEqual, 1)
				So(c.Flows[r.StatsFlowHash()], ShouldNotBeNil)
				So(c.Flows[r.StatsFlowHash()].Count, ShouldEqual, 1)
			})

			Convey("When I add a second flow that matches", func() {
				r := &collector.FlowRecord{
					ContextID:   "1",
					Source:      collector.NewEndPoint(collector.EnpointTypePU, "A", collector.OptionEndPointIPPort("1.1.1.1", 0)),
					Destination: collector.NewEndPoint(collector.EnpointTypePU, "B", collector.OptionEndPointIPPort("2.2.2.2", 80)),
					Count:       10,
					Tags:        policy.NewTagStore(),
					L4Protocol:  packet.IPProtocolTCP,
				}
				c.CollectFlowEvent(r)
				Convey("The flow should be in the cache", func() {
					So(len(c.Flows), ShouldEqual, 1)
					So(c.Flows[r.StatsFlowHash()], ShouldNotBeNil)
					So(c.Flows[r.StatsFlowHash()].Count, ShouldEqual, 11)
				})
			})

			Convey("When I add a third flow that doesn't  matche the previous flows ", func() {
				r := &collector.FlowRecord{
					ContextID:   "1",
					Source:      collector.NewEndPoint(collector.EnpointTypePU, "C", collector.OptionEndPointIPPort("3.3.3.3", 0)),
					Destination: collector.NewEndPoint(collector.EnpointTypePU, "B", collector.OptionEndPointIPPort("4.4.4.4", 80)),
					Count:       33,
					Tags:        policy.NewTagStore(),
					L4Protocol:  packet.IPProtocolTCP,
				}
				c.CollectFlowEvent(r)
				Convey("The flow should be in the cache", func() {
					So(len(c.Flows), ShouldEqual, 2)
					So(c.Flows[r.StatsFlowHash()], ShouldNotBeNil)
					So(c.Flows[r.StatsFlowHash()].Count, ShouldEqual, 33)
				})
			})
		})
	})
}
