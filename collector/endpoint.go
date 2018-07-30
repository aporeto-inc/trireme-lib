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
