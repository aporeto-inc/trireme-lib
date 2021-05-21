package extractors

import (
	"crypto/md5"
	"io"
	"os"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/fqdn"
)

// ComputeFileMd5 computes the Md5 of a file
func ComputeFileMd5(filePath string) ([]byte, error) {

	var result []byte
	file, err := os.Open(filePath)
	if err != nil {
		return result, err
	}
	defer file.Close() // nolint: errcheck

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
		globalHostname <- fqdn.Find()

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
