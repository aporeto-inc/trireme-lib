package flowstats

import (
	"net"
	"net/http"

	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/apiauth"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// ConnectionState captures the connection state. This state
// is passed to the RoundTripper for any last minute adjustments.
type ConnectionState struct {
	Stats  *collector.FlowRecord
	Cookie *http.Cookie
}

// NewAppConnectionState will create the initial connection state object.
func NewAppConnectionState(nativeID string, r *http.Request, authRequest *apiauth.Request, resp *apiauth.AppAuthResponse) *ConnectionState {

	sourceIP := "0.0.0.0/0"
	sourcePort := 0
	if sourceAddress, err := net.ResolveTCPAddr("tcp", r.RemoteAddr); err == nil {
		sourceIP = sourceAddress.IP.String()
		sourcePort = sourceAddress.Port
	}

	var tags policy.TagStore
	if resp.PUContext.Annotations() != nil {
		tags = *resp.PUContext.Annotations()
	}

	return &ConnectionState{
		Stats: &collector.FlowRecord{
			ContextID: nativeID,
			Destination: collector.EndPoint{
				URI:        r.Method + " " + r.RequestURI,
				HTTPMethod: r.Method,
				Type:       collector.EndPointTypeExternalIP,
				Port:       uint16(authRequest.OriginalDestination.Port),
				IP:         authRequest.OriginalDestination.IP.String(),
				ID:         resp.NetworkServiceID,
			},
			Source: collector.EndPoint{
				Type:       collector.EndPointTypePU,
				ID:         resp.PUContext.ManagementID(),
				IP:         sourceIP,
				Port:       uint16(sourcePort),
				HTTPMethod: r.Method,
				URI:        r.Method + " " + r.RequestURI,
			},
			Action:      resp.Action,
			L4Protocol:  packet.IPProtocolTCP,
			ServiceType: policy.ServiceHTTP,
			ServiceID:   resp.ServiceID,
			Tags:        tags.GetSlice(),
			Namespace:   resp.PUContext.ManagementNamespace(),
			PolicyID:    resp.NetworkPolicyID,
			Count:       1,
		},
	}
}

// NewNetworkConnectionState will create the initial connection state object.
func NewNetworkConnectionState(nativeID string, userID string, r *apiauth.Request, d *apiauth.NetworkAuthResponse) *ConnectionState {

	var mgmtID, namespace, serviceID string
	var tags policy.TagStore

	if d.PUContext != nil {
		mgmtID = d.PUContext.ManagementID()
		namespace = d.PUContext.ManagementNamespace()
		if d.PUContext.Annotations() != nil {
			tags = *d.PUContext.Annotations()
		}
		serviceID = d.ServiceID
	} else {
		mgmtID = collector.DefaultEndPoint
		namespace = collector.DefaultEndPoint
		tags = *policy.NewTagStore()
		serviceID = collector.DefaultEndPoint
	}

	sourceType := collector.EndPointTypeExternalIP
	sourceID := collector.DefaultEndPoint
	networkPolicyID := collector.DefaultEndPoint
	action := policy.Reject | policy.Log

	if d != nil {
		sourceType = d.SourceType
		if sourceType == collector.EndPointTypeClaims {
			sourceType = collector.EndPointTypeExternalIP
		}

		switch d.SourceType {
		case collector.EndPointTypePU:
			sourceID = d.SourcePUID
		case collector.EndPointTypeClaims:
			sourceID = d.NetworkServiceID
		default:
			sourceID = d.NetworkServiceID
		}

		if d.NetworkPolicyID != "" {
			networkPolicyID = d.NetworkPolicyID
		}
		action = d.Action
	}

	c := &ConnectionState{
		Stats: &collector.FlowRecord{
			ContextID: nativeID,
			Destination: collector.EndPoint{
				ID:         mgmtID,
				Type:       collector.EndPointTypePU,
				IP:         r.OriginalDestination.IP.String(),
				Port:       uint16(r.OriginalDestination.Port),
				URI:        r.Method + " " + r.RequestURI,
				HTTPMethod: r.Method,
				UserID:     userID,
			},
			Source: collector.EndPoint{
				ID:     sourceID,
				Type:   sourceType,
				IP:     r.SourceAddress.IP.String(),
				Port:   uint16(r.SourceAddress.Port),
				UserID: userID,
			},
			Action:      action,
			L4Protocol:  packet.IPProtocolTCP,
			ServiceType: policy.ServiceHTTP,
			PolicyID:    networkPolicyID,
			ServiceID:   serviceID,
			Tags:        tags.GetSlice(),
			Namespace:   namespace,
			Count:       1,
		},
	}

	if d != nil {
		if d.Action.Rejected() {
			c.Stats.DropReason = d.DropReason
		}

		if d.ObservedPolicyID != "" {
			c.Stats.ObservedPolicyID = d.ObservedPolicyID
			c.Stats.ObservedAction = d.ObservedAction
		}

		c.Cookie = d.Cookie
	}

	return c
}
