package nfqdatapath

import (
	"encoding/json"
	"fmt"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/trireme-lib/v11/collector"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/secrets"
)

type myMatcher struct {
	x interface{}
}

func (m *myMatcher) Matches(x interface{}) bool {
	f1 := m.x.(*collector.FlowRecord)
	f2 := x.(*collector.FlowRecord)

	return f1.Destination.IP == f2.Destination.IP &&
		f1.Source.IP == f2.Source.IP &&
		f1.Destination.Port == f2.Destination.Port &&
		f1.Action == f2.Action &&
		f1.Count == f2.Count &&
		f1.DropReason == f2.DropReason
}

func (m *myMatcher) String() string {

	out, err := json.Marshal(m.x)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("is equal to %v", string(out))
}

type myGotFormatter struct{}

func (g *myGotFormatter) Got(got interface{}) string {

	out, err := json.Marshal(got)
	if err != nil {
		panic(err)
	}

	return string(out)
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
	x interface{}
}

func (m *myCounterMatcher) Matches(x interface{}) bool {
	f1 := m.x.(*collector.CounterReport)
	f2 := x.(*collector.CounterReport)
	if f2.Namespace != "/ns1" {
		return true
	}

	return f1.ContextID == f2.ContextID && f1.Counters[pucontext.ErrNonPUTraffic].Value == 0

}

func (m *myCounterMatcher) String() string {
	return fmt.Sprintf("is equal to %v", m.x)
}

// MyCounterMatcher custom matcher for counter record
func MyCounterMatcher(x interface{}) gomock.Matcher {
	return &myCounterMatcher{x: x}
}

type fakeSecrets struct {
	id string
	*secrets.NullPKI
}

func (f *fakeSecrets) setID(id string) {
	f.id = id
}

func (f *fakeSecrets) getID() string {
	return f.id
}
