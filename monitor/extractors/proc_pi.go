package extractors

import (
	"crypto/md5"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
)

// computeFileMd5 computes the Md5 of a file
func computeFileMd5(filePath string) ([]byte, error) {

	var result []byte
	file, err := os.Open(filePath)
	if err != nil {
		return result, err
	}
	defer file.Close() //nolint : errcheck

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return result, err
	}

	return hash.Sum(result), nil
}

func findFQDN(expiration time.Duration) string {

	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}

	// Try to find FQDN
	globalHostname := make(chan string, 1)
	go func() {
		addrs, err := net.LookupIP(hostname)
		if err != nil {
			globalHostname <- hostname
			return
		}

		for _, addr := range addrs {
			ip, err := addr.MarshalText()
			if err != nil {
				globalHostname <- hostname
				return
			}
			hosts, err := net.LookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				globalHostname <- hostname
				return
			}
			fqdn := hosts[0]
			globalHostname <- strings.TrimSuffix(fqdn, ".") // return fqdn without trailing dot
		}
	}()

	// Use OS hostname if we dont hear back in a second
	select {
	case <-time.After(expiration):
		return hostname
	case name := <-globalHostname:
		return name
	}
}

// policyExtensions retrieves policy extensions. Moving this function from extractor package.
func policyExtensions(runtime policy.RuntimeReader) (extensions policy.ExtendedMap) {

	if runtime == nil {
		return nil
	}

	if runtime.Options().PolicyExtensions == nil {
		return nil
	}

	if extensions, ok := runtime.Options().PolicyExtensions.(policy.ExtendedMap); ok {
		return extensions
	}
	return nil
}

// IsHostmodePU returns true if puType stored by policy extensions is hostmode PU
func IsHostmodePU(runtime policy.RuntimeReader, mode constants.ModeType) bool {

	if runtime == nil {
		return false
	}

	if mode != constants.LocalServer {
		return false
	}

	return runtime.PUType() == common.HostPU || runtime.PUType() == common.HostNetworkPU
}

// IsHostPU returns true if puType stored by policy extensions is host PU
func IsHostPU(runtime policy.RuntimeReader, mode constants.ModeType) bool {

	if runtime == nil {
		return false
	}

	if mode != constants.LocalServer {
		return false
	}

	return runtime.PUType() == common.HostPU
}
