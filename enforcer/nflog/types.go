package nflog

import "net"

// Packet holds the info about one packet
//
// Addr is a net.IP which is a []byte converted into a string This
// won't be a nice UTF-8 string but will preserve the bytes and can be
// used as a hash key
type Packet struct {
	Prefix          string
	Direction       IPDirection
	SourceAddr      net.IP
	DestinationAddr net.IP
	Length          int
}
