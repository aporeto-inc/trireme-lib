package remoteenforcer

import (
	"testing"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/policy"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewCollector(t *testing.T) {
	Convey("When I create a new collector", t, func() {
		c := NewCollector()
		Convey("The collector should not be nil ", func() {
			So(c, ShouldNotBeNil)
			So(c.Flows, ShouldNotBeNil)
		})
	})
}

func TestCollectFlowEvent(t *testing.T) {
	Convey("Given a stats collector", t, func() {
		c := &CollectorImpl{
			Flows: map[string]*collector.FlowRecord{},
		}

		Convey("When I add a flow event", func() {
			r := &collector.FlowRecord{
				ContextID:       "1",
				SourceID:        "A",
				DestinationID:   "B",
				SourceIP:        "1.1.1.1",
				DestinationIP:   "2.2.2.2",
				DestinationPort: 80,
				Count:           0,
				Tags:            &policy.TagsMap{},
			}
			c.CollectFlowEvent(r)

			Convey("The flow should be in the cache", func() {
				So(len(c.Flows), ShouldEqual, 1)
				So(c.Flows[collector.StatsFlowHash(r)], ShouldNotBeNil)
				So(c.Flows[collector.StatsFlowHash(r)].Count, ShouldEqual, 1)
			})

			Convey("When I add a second flow that matches", func() {
				r := &collector.FlowRecord{
					ContextID:       "1",
					SourceID:        "A",
					DestinationID:   "B",
					SourceIP:        "1.1.1.1",
					DestinationIP:   "2.2.2.2",
					DestinationPort: 80,
					Count:           10,
					Tags:            &policy.TagsMap{},
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
					ContextID:       "1",
					SourceID:        "C",
					DestinationID:   "D",
					SourceIP:        "3.3.3.3",
					DestinationIP:   "4.4.4.4",
					DestinationPort: 80,
					Count:           33,
					Tags:            &policy.TagsMap{},
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
