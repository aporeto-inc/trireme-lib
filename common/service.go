package common

import (
	"net"

	"go.aporeto.io/trireme-lib/v11/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/v11/utils/portspec"
)

// Service is a protocol/port service of interest - used to pass user requests
type Service struct {
	// Ports are the corresponding ports
	Ports *portspec.PortSpec `json:"ports,omitempty"`

	// Port is the service port. This has been deprecated and will be removed in later releases 01/13/2018
	Port uint16

	// Protocol is the protocol number
	Protocol uint8 `json:"protocol,omitempty"`

	// Addresses are the IP addresses. An empty list means 0.0.0.0/0
	Addresses []*net.IPNet `json:"addresses,omitempty"`

	// FQDNs is the list of FQDNs for the service.
	FQDNs []string `json:"fqdns,omitempty"`
}

// ConvertServicesToPortList converts an array of services to a port list
func ConvertServicesToPortList(services []Service) string {

	portlist := ""
	for _, s := range services {
		portlist = portlist + s.Ports.String() + ","
	}

	if len(portlist) == 0 {
		portlist = "0"
	} else {
		portlist = portlist[:len(portlist)-1]
	}

	return portlist
}

// ConvertServicesToProtocolPortList converts an array of services to tcp/udp port list
func ConvertServicesToProtocolPortList(services []Service) (string, string) {

	tcpPortlist := ""
	udpPortlist := ""
	for _, s := range services {
		if s.Protocol == packet.IPProtocolTCP {
			tcpPortlist = tcpPortlist + s.Ports.String() + ","
		} else {
			udpPortlist = udpPortlist + s.Ports.String() + ","
		}
	}

	if len(tcpPortlist) == 0 {
		tcpPortlist = "0"
	} else {
		tcpPortlist = tcpPortlist[:len(tcpPortlist)-1]
	}

	if len(udpPortlist) == 0 {
		udpPortlist = "0"
	} else {
		udpPortlist = udpPortlist[:len(udpPortlist)-1]
	}

	return tcpPortlist, udpPortlist
}
