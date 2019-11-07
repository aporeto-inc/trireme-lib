// +build !windows

package cert

import (
	"crypto/x509"
)

// GetSystemCertPool just calls the Go implementation
func GetSystemCertPool() (*x509.CertPool, error) {
	return x509.SystemCertPool()
}
