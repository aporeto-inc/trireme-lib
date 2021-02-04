package fqdn

import (
	"net"
	"os"
	"strings"
	"sync"
)

// defining os and net package functions in their own variables
// so that we can mock them for unit tests
var (
	osHostname    = os.Hostname
	netLookupIP   = net.LookupIP
	netLookupAddr = net.LookupAddr
)

const unknownHostname = "unknown"

// InitializeAlternativeHostname can be used to set an alternative hostname that is being used by `FindFQDN`.
// The enforcer can use this during startup to provide an alternative value.
func InitializeAlternativeHostname(hostname string) {
	if hostname != "" {
		alternativeHostnameOnce.Do(func() {
			alternativeHostnameLock.Lock()

			alternativeHostname = hostname

			alternativeHostnameLock.Unlock()
		})
	}
}

func getAlternativeHostname() string {
	alternativeHostnameLock.RLock()
	defer alternativeHostnameLock.RUnlock()
	return alternativeHostname
}

var (
	alternativeHostnameOnce = &sync.Once{}
	alternativeHostnameLock sync.RWMutex
	alternativeHostname     string
)

// Find returns fqdn. It uses the following algorithm:
// First of all, it will return the globally set alternative hostname if it has been initialized with previously with `IntializeAlternativeHostname`
// If this is not set, it will try to determine the hostname, resolve the hostname to an IP,
// and based on the hostname it will perform a reverse DNS lookup for the IP.
// The first entry of the reverse DNS lookup will be returned.
// If there are any errors during this process, this function will return "unknown".
// It will never return an empty string.
func Find() string {

	alternativeHostname := getAlternativeHostname()
	if alternativeHostname != "" {
		return alternativeHostname
	}

	hostname, err := osHostname()
	if err != nil {
		return unknownHostname
	}

	addrs, err := netLookupIP(hostname)
	if err != nil {
		return hostname
	}

	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ip, err := ipv4.MarshalText()
			if err != nil {
				return hostname
			}
			hosts, err := netLookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				return hostname
			}
			fqdn := hosts[0]
			return strings.TrimSuffix(fqdn, ".") // return fqdn without trailing dot
		}
	}

	return hostname
}
