package httpproxy

import (
	"net"
	"net/http"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
)

// connectionState captures the connection state. This state
// is passed to the RoundTripper for any last minute adjustments.
type connectionState struct {
	stats  *collector.FlowRecord
	cookie *http.Cookie
}

// newAppConnectionState will create the initial connection state object.
func newAppConnectionState(nativeID, serviceID string, p *pucontext.PUContext, r *http.Request, originalDestination *net.TCPAddr) *connectionState {
	return &connectionState{
		stats: &collector.FlowRecord{
			ContextID: nativeID,
			Destination: &collector.EndPoint{
				URI:        r.Method + " " + r.RequestURI,
				HTTPMethod: r.Method,
				Type:       collector.EndPointTypeExternalIP,
				Port:       uint16(originalDestination.Port),
				IP:         originalDestination.IP.String(),
				ID:         collector.DefaultEndPoint,
			},
			Source: &collector.EndPoint{
				Type: collector.EnpointTypePU,
				ID:   p.ManagementID(),
				IP:   "0.0.0.0/0",
			},
			Action:      policy.Reject,
			L4Protocol:  packet.IPProtocolTCP,
			ServiceType: policy.ServiceHTTP,
			ServiceID:   serviceID,
			Tags:        p.Annotations(),
			Count:       1,
		},
	}
}

// newNetworkConnectionState will create the initial connection state object.
func newNetworkConnectionState(nativeID string, r *http.Request, source, dest *net.TCPAddr) *connectionState {
	return &connectionState{
		stats: &collector.FlowRecord{
			ContextID: nativeID,
			Destination: &collector.EndPoint{
				URI:        r.Method + " " + r.RequestURI,
				HTTPMethod: r.Method,
				Type:       collector.EnpointTypePU,
				IP:         dest.IP.String(),
				Port:       uint16(dest.Port),
			},
			Source: &collector.EndPoint{
				Type: collector.EndPointTypeExternalIP,
				IP:   source.IP.String(),
				ID:   collector.DefaultEndPoint,
			},
			Action:      policy.Reject,
			L4Protocol:  packet.IPProtocolTCP,
			ServiceType: policy.ServiceHTTP,
			PolicyID:    "default",
			Count:       1,
		},
	}
}
