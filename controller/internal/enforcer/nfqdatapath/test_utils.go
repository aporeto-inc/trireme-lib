package nfqdatapath

import (
	"fmt"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/trireme-lib/collector"
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
