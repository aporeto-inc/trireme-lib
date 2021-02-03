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
	// return with the global alternative hostname if this is what we really want to do
	alternativeHostname := getAlternativeHostname()
	if alternativeHostname != "" {
		return alternativeHostname
	}

	// for some cloud providers (like AWS at some point) we prefer different FQDNs
	// return with th

	hostnameRaw, err := osHostname()
	if err != nil {
		return unknownHostname
	}

	// net.LookupIP will actually error if hostname is empty
	// so if there is no hostname set in the kernel, also return unknown
	// as in all other error cases we want to return a valid string
	// make sure that it is set to either os.Hostname or "unknown", but is never empty
	hostname := hostnameRaw
	if hostnameRaw == "" {
		hostname = unknownHostname
	}

	addrs, err := netLookupIP(hostnameRaw)
	if err != nil {
		return hostname
	}

	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ip, err := ipv4.MarshalText()
			if err != nil {
				// impossible case and only possible if there is a bug in golang:
				// this will only error if this is not a valid IP address
				// To4() already proves that
				continue
			}
			hosts, err := netLookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				continue
			}
			fqdn := hosts[0]
			ret := strings.TrimSuffix(fqdn, ".") // return fqdn without trailing dot
			if ret != "" {
				return ret
			}
		}
		if ipv6 := addr.To16(); ipv6 != nil {
			ip, err := ipv6.MarshalText()
			if err != nil {
				// impossible case and only possible if there is a bug in golang:
				// this will only error if this is not a valid IP address
				// To16() already proves that
				continue
			}
			hosts, err := netLookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				continue
			}
			fqdn := hosts[0]
			ret := strings.TrimSuffix(fqdn, ".") // return fqdn without trailing dot
			if ret != "" {
				return ret
			}
		}
	}

	// fall back to os.Hostname or unknown if none of that worked
	return hostname
}
