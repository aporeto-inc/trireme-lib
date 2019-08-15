package apiauth

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
)

// Request captures all the important items of request that are needed
// for processing the authorization decision.
type Request struct {

	// SourceAddress, only required for network authorization requests.
	SourceAddress *net.TCPAddr

	// OriginalDestination required for all requests.
	OriginalDestination *net.TCPAddr

	// HTTP header information.
	Method     string
	URL        *url.URL
	RequestURI string
	Header     http.Header
	Cookie     *http.Cookie

	// TLS information. This is optional if mutual TLS based authorization
	// must be supported.
	TLS *tls.ConnectionState
}

// NetworkAuthResponse is the decision of the authorization process.
type NetworkAuthResponse struct {

	// Discovered service context and associated information.
	PUContext *pucontext.PUContext
	ServiceID string
	Namespace string

	// Network policy ID and service that affect the call.
	NetworkPolicyID  string
	NetworkServiceID string

	// Definition of the source.
	SourceType collector.EndPointType
	SourcePUID string

	// Action associated with the response and DropReason if dropped.
	Action     policy.ActionType
	DropReason string

	// Redirect infromation that should be used by the responder.
	Redirect    bool
	RedirectURI string
	Cookie      *http.Cookie
	Data        string
	Header      http.Header

	// UserAttrbutes discovered from the tokens.
	UserAttributes []string

	// TLSListener determines that TLS must be re-initiated towards
	// the listener.
	TLSListener bool
}

// AppAuthResponse is the decision of the authorization process.
type AppAuthResponse struct {
	// Discovered context and service information
	PUContext *pucontext.PUContext
	ServiceID string
	External  bool

	// Network policy ID and service ID that affect the response.
	NetworkPolicyID  string
	NetworkServiceID string

	// Action of the response and DropReason if the call must be dropped.
	Action     policy.ActionType
	DropReason string

	// Resolved token
	Token string

	// HookMethod is the corresponding HTTP rule hook method
	HookMethod string

	// TLSListener indicates that the external entity is a TLS listener,
	// and we must start a TLS session. Only applies to External connections.
	TLSListener bool
}

// AuthError implements the error interface, but provides additional information
// for the types of errors discovered.
type AuthError struct {
	status  int
	message string
	err     error
}

// Error implement the string interface of error.
func (a *AuthError) Error() string {
	return a.message
}

// Message returns the message of the error.
func (a *AuthError) Message() string {
	return a.message
}

// Status returns the status of the message.
func (a *AuthError) Status() int {
	return a.status
}
