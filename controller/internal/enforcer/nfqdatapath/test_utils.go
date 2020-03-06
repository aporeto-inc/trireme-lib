package nfqdatapath

import (
	"fmt"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/counters"
)

type myMatcher struct {
	x interface{}
}

func (m *myMatcher) Matches(x interface{}) bool {
	f1 := m.x.(*collector.FlowRecord)
	f2 := x.(*collector.FlowRecord)

	if f1.Destination.IP == f2.Destination.IP && f1.Source.IP == f2.Source.IP && f1.Destination.Port == f2.Destination.Port && f1.Action == f2.Action && f1.Count == f2.Count {

		return true
	}

	return false
}

func (m *myMatcher) String() string {
	return fmt.Sprintf("is equal to %v", m.x)
}

// MyMatcher returns gomock matcher
func MyMatcher(x interface{}) gomock.Matcher {
	return &myMatcher{x: x}
}

type packetEventMatcher struct {
	x interface{}
}

func (p *packetEventMatcher) Matches(x interface{}) bool {
	f1 := p.x.(*collector.PacketReport)
	f2 := x.(*collector.PacketReport)
	return f1.DestinationIP == f2.DestinationIP
}

func (p *packetEventMatcher) String() string {
	return fmt.Sprintf("is equal to %v", p.x)
}

// PacketEventMatcher return gomock matcher
func PacketEventMatcher(x interface{}) gomock.Matcher {
	return &packetEventMatcher{x: x}
}

type myCounterMatcher struct {
	x interface{}
}

func (m *myCounterMatcher) Matches(x interface{}) bool {
	f1 := m.x.(*collector.CounterReport)
	f2 := x.(*collector.CounterReport)
	if f2.Namespace != "/ns1" {
		return true
	}

	return f1.PUID == f2.PUID && f1.Counters[counters.ErrNonPUTraffic] == 0

}

func (m *myCounterMatcher) String() string {
	return fmt.Sprintf("is equal to %v", m.x)
}

// MyCounterMatcher custom matcher for counter record
func MyCounterMatcher(x interface{}) gomock.Matcher {
	return &myCounterMatcher{x: x}
}
