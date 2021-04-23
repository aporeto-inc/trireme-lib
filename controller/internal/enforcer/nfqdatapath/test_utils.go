package nfqdatapath

import (
	"encoding/json"
	"fmt"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets/mocksecrets"
)

type endpointTypeMatcher struct {
	x           interface{}
	baseMatcher *myMatcher
}

func (m *endpointTypeMatcher) Matches(x interface{}) bool {
	f1 := m.x.(*collector.FlowRecord)
	f2 := x.(*collector.FlowRecord)

	defaultChecks := f1.Destination.Type == f2.Destination.Type &&
		f1.Destination.ID == f2.Destination.ID &&
		f1.Source.Type == f2.Source.Type &&
		f1.Source.ID == f2.Source.ID

	if m.baseMatcher != nil {
		return defaultChecks && m.baseMatcher.Matches(x)
	}

	return defaultChecks
}

func (m *endpointTypeMatcher) String() string {

	out, err := json.Marshal(m.x)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("is equal to %v", string(out))
}

// EndpointTypeMatcher extends MyMatcher to match endpoint Type and ID
func EndpointTypeMatcher(x interface{}) gomock.Matcher {
	return gomock.GotFormatterAdapter(&myGotFormatter{}, &endpointTypeMatcher{x: x, baseMatcher: &myMatcher{x: x}})
}

type myMatcher struct {
	x interface{}
}

func (m *myMatcher) Matches(x interface{}) bool {
	f1 := m.x.(*collector.FlowRecord)
	f2 := x.(*collector.FlowRecord)

	defaultChecks := f1.Destination.IP == f2.Destination.IP &&
		f1.Source.IP == f2.Source.IP &&
		f1.Destination.Port == f2.Destination.Port &&
		f1.Action == f2.Action &&
		f1.Count == f2.Count &&
		f1.DropReason == f2.DropReason

	return defaultChecks
}

func (m *myMatcher) String() string {

	f := m.x.(*collector.FlowRecord)
	return fmt.Sprintf("%d, %v, %v, %d, %d, %s", f.Count, f.Source.IP, f.Destination.IP, f.Destination.Port, f.Action, f.DropReason)
}

type myGotFormatter struct{}

func (g *myGotFormatter) Got(got interface{}) string {

	f := got.(*collector.FlowRecord)
	return fmt.Sprintf("%d, %v, %v, %d, %d, %s", f.Count, f.Source.IP, f.Destination.IP, f.Destination.Port, f.Action, f.DropReason)
}

// MyMatcher returns gomock matcher
func MyMatcher(x interface{}) gomock.Matcher {
	return gomock.GotFormatterAdapter(&myGotFormatter{}, &myMatcher{x: x})
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
	x *collector.CounterReport
}

func (m *myCounterMatcher) Matches(x interface{}) bool {

	f := x.(*collector.CounterReport)
	if f.Namespace != "/ns1" {
		return true
	}
	return m.x.PUID == f.PUID && m.x.Namespace == f.Namespace
}

func (m *myCounterMatcher) String() string {
	return fmt.Sprintf("is equal to %v", m.x)
}

// MyCounterMatcher custom matcher for counter record
func MyCounterMatcher(x *collector.CounterReport) gomock.Matcher {
	return &myCounterMatcher{x: x}
}

type fakeSecrets struct {
	id string
	*mocksecrets.MockSecrets
}

func (f *fakeSecrets) setID(id string) {
	f.id = id
}

func (f *fakeSecrets) getID() string {
	return f.id
}
