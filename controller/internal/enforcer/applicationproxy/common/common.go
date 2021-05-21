package common

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"

	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// ListenerType are the types of listeners that can be used.
type ListenerType int

// Values of ListenerType
const (
	TCPApplication ListenerType = iota
	TCPNetwork
	HTTPApplication
	HTTPNetwork
	HTTPSApplication
	HTTPSNetwork
)

// ExtractExtension returns true and the value of the given oid If any.
func ExtractExtension(oid asn1.ObjectIdentifier, extensions []pkix.Extension) (bool, []byte) {

	for _, ext := range extensions {
		if !ext.Id.Equal(oid) {
			continue
		}

		return true, ext.Value
	}

	return false, nil
}

// GetTLSServerName provides the server name to use in TLS config based on service configuration and destination IP.
func GetTLSServerName(
	addrAndPort string,
	service *policy.ApplicationService,
) (name string, err error) {

	if service != nil && service.NetworkInfo != nil && len(service.NetworkInfo.FQDNs) != 0 {
		name = service.NetworkInfo.FQDNs[0]
		return name, nil
	}

	name, _, err = net.SplitHostPort(addrAndPort)
	return name, err
}
