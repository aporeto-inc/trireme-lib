package acls

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Address is a parsed IP address or CIDR
type Address struct {
	IP      net.IP
	Mask    int
	NoMatch bool
}

// ParseAddress parses `address` as an IP or CIDR address - based on the notation that we allow in our backend.
// If the address is prefixed with a "!"", then the NoMatch attribute will be true.
// If the Address is of the format "IP/BitMask" (e.g. 192.0.2.0/24), then the mask will be set to 24.
// If the address is of the form "IP" (e.g. 192.0.2.1), then the mask will be added automatically.
func ParseAddress(address string) (*Address, error) {
	var mask int
	var err error
	parts := strings.Split(address, "/")
	nomatch := strings.HasPrefix(parts[0], "!")
	if nomatch {
		parts[0] = parts[0][1:]
	}
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid ip address: %s", parts[0])
	}

	if len(parts) == 1 {
		if ip.To4() != nil {
			mask = 32
		} else {
			mask = 128
		}
	} else {
		mask, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid mask '%s': %w", parts[1], err)
		}
	}

	return &Address{IP: ip, Mask: mask, NoMatch: nomatch}, nil
}
