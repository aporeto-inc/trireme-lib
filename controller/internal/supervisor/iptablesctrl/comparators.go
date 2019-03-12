package iptablesctrl

import "go.aporeto.io/trireme-lib/policy"

func testObserveContinue(p *policy.FlowPolicy) bool {
	return p.ObserveAction.ObserveContinue()
}

func testNotObserved(p *policy.FlowPolicy) bool {
	return !p.ObserveAction.Observed()
}

func testObserveApply(p *policy.FlowPolicy) bool {
	return p.ObserveAction.ObserveApply()
}

func testReject(p *policy.FlowPolicy) bool {
	return (p.Action&policy.Reject != 0)
}

func testAccept(p *policy.FlowPolicy) bool {
	return (p.Action&policy.Accept != 0)
}
