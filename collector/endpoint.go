package collector

// EndPointType is the type of an endpoint (PU or an external IP address )
type EndPointType byte

const (
	// EndPointTypeExternalIP indicates that the endpoint is an external IP address
	EndPointTypeExternalIP EndPointType = iota
	// EnpointTypePU indicates that the endpoint is a PU.
	EnpointTypePU
	// EndpointTypeClaims indicates that the endpoint is of type claims.
	EndpointTypeClaims
)

func (e *EndPointType) String() string {

	switch *e {
	case EndPointTypeExternalIP:
		return "ext"
	case EnpointTypePU:
		return "pu"
	case EndpointTypeClaims:
		return "claims"
	}

	return "pu" // backward compatibility (CS: 04/24/2018)
}

// EndPoint is a structure that holds all the endpoint information
type EndPoint struct {
	ID         string
	IP         string
	URI        string
	HTTPMethod string
	UserID     string
	Type       EndPointType
	Port       uint16
}

// EndPointOption is provided using functional arguments.
type EndPointOption func(*EndPoint)

// OptionEndPointIPPort is an option to setup IP and port.
func OptionEndPointIPPort(ip string, port uint16) EndPointOption {
	return func(e *EndPoint) {
		e.IP = ip
		e.Port = port
	}
}

// OptionEndPointUserID is an option to setup user-id.
func OptionEndPointUserID(id string) EndPointOption {
	return func(e *EndPoint) {
		e.UserID = id
	}
}

// OptionEndPointHTTP is an option to setup http information.
func OptionEndPointHTTP(uri, method string) EndPointOption {
	return func(e *EndPoint) {
		e.URI = uri
		e.HTTPMethod = method
	}
}

// NewEndPoint creates a new endpoint definition.
func NewEndPoint(t EndPointType, id string, opts ...EndPointOption) *EndPoint {
	e := &EndPoint{
		Type: t,
		ID:   id,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}
