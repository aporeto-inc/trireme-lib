// +build linux

package tcp

import (
	"fmt"
	"net"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
)

// CompleteEndPointAuthorization -- Aporeto Handshake on top of a completed connection
// We will define states here equivalent to SYN_SENT AND SYN_RECEIVED
func (p *Proxy) CompleteEndPointAuthorization(downIP net.IP, downPort int, upConn, downConn net.Conn) (bool, error) {

	// If the backend is not a local IP it means that we are a client.
	if p.isLocal(upConn) {
		return p.StartClientAuthStateMachine(downIP, downPort, downConn)
	}

	isEncrypted, err := p.StartServerAuthStateMachine(downIP, downPort, upConn)
	if err != nil {
		return false, err
	}

	return isEncrypted, nil
}

// CheckExternalNetwork checks if external network access is allowed
func (p *Proxy) CheckExternalNetwork(puContext *pucontext.PUContext, IP net.IP, Port int, flowproperties *proxyFlowProperties, network bool) (bool, bool, error) {
	var networkReport *policy.FlowPolicy
	var networkPolicy *policy.FlowPolicy
	var noNetAccessPolicy error
	if network {
		networkReport, networkPolicy, noNetAccessPolicy = puContext.ApplicationACLPolicyFromAddr(IP, uint16(Port))
	} else {
		networkReport, networkPolicy, noNetAccessPolicy = puContext.NetworkACLPolicyFromAddr(IP, uint16(Port))

	}
	if noNetAccessPolicy == nil && networkPolicy.Action.Rejected() {
		p.reportRejectedFlow(flowproperties, puContext.ManagementID(), networkPolicy.ServiceID, puContext, collector.PolicyDrop, networkReport, networkPolicy)
		return false, false, fmt.Errorf("Unauthorized by Application ACLs")
	}
	return false, false, nil
}
