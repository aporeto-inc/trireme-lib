package statscollector

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/policy"
)

func TestNewCollector(t *testing.T) {
	Convey("When I create a new collector", t, func() {
		c := NewCollector()
		Convey("The collector should not be nil ", func() {
			So(c, ShouldNotBeNil)
			So(c.GetFlowRecords(), ShouldBeNil)
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
				ContextID: "1",
				Source: &collector.EndPoint{
					ID:   "A",
					IP:   "1.1.1.1",
					Type: collector.EnpointTypePU,
				},
				Destination: &collector.EndPoint{
					ID:   "B",
					IP:   "2.2.2.2",
					Type: collector.EnpointTypePU,
					Port: 80,
				},
				Count:      0,
				Tags:       policy.NewTagStore(),
				L4Protocol: packet.IPProtocolTCP,
			}
			c.CollectFlowEvent(r)

			Convey("The flow should be in the cache", func() {
				So(len(c.Flows), ShouldEqual, 1)
				So(c.Flows[collector.StatsFlowHash(r)], ShouldNotBeNil)
				So(c.Flows[collector.StatsFlowHash(r)].Count, ShouldEqual, 1)
			})

			Convey("When I add a second flow that matches", func() {
				r := &collector.FlowRecord{
					ContextID: "1",
					Source: &collector.EndPoint{
						ID:   "A",
						IP:   "1.1.1.1",
						Type: collector.EnpointTypePU,
					},
					Destination: &collector.EndPoint{
						ID:   "B",
						IP:   "2.2.2.2",
						Type: collector.EnpointTypePU,
						Port: 80,
					},
					Count:      10,
					Tags:       policy.NewTagStore(),
					L4Protocol: packet.IPProtocolTCP,
				}
				c.CollectFlowEvent(r)
				Convey("The flow should be in the cache", func() {
					So(len(c.Flows), ShouldEqual, 1)
					So(c.Flows[collector.StatsFlowHash(r)], ShouldNotBeNil)
					So(c.Flows[collector.StatsFlowHash(r)].Count, ShouldEqual, 11)
				})
			})

			Convey("When I add a third flow that doesn't  matche the previous flows ", func() {
				r := &collector.FlowRecord{
					ContextID: "1",
					Source: &collector.EndPoint{
						ID:   "C",
						IP:   "3.3.3.3",
						Type: collector.EnpointTypePU,
					},
					Destination: &collector.EndPoint{
						ID:   "D",
						IP:   "4.4.4.4",
						Type: collector.EnpointTypePU,
						Port: 80,
					},
					Count:      33,
					Tags:       policy.NewTagStore(),
					L4Protocol: packet.IPProtocolTCP,
				}
				c.CollectFlowEvent(r)
				Convey("The flow should be in the cache", func() {
					So(len(c.Flows), ShouldEqual, 2)
					So(c.Flows[collector.StatsFlowHash(r)], ShouldNotBeNil)
					So(c.Flows[collector.StatsFlowHash(r)].Count, ShouldEqual, 33)
				})
			})
		})
	})
}

func TestGetAllDataPathPacketRecords(t *testing.T) {
	Convey("Given i collect a new collector", t, func() {
		c := NewCollector()
		Convey("I trace single packet", func() {
			c.CollectPacketEvent(&collector.PacketReport{
				DestinationIP: "1.2.3.4",
			})
			records := c.GetReports()
			So(len(records), ShouldEqual, 1)
		})

	})

}

func TestAllCounterReports(t *testing.T) {
	Convey("Given i collect a new collector", t, func() {
		c := NewCollector()
		c.(*collectorImpl).Reports = make(chan *Report, 1)
		Convey("I trace a single packet", func() {
			c.CollectCounterEvent(&collector.CounterReport{})
			records := c.GetReports()
			So(len(records), ShouldEqual, 1)
			c.CollectCounterEvent(&collector.CounterReport{})
			records = c.GetReports()
			So(len(records), ShouldEqual, 1)
		})
	})
}
