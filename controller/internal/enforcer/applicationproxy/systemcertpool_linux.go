// +build !windows

package applicationproxy

import (
	"crypto/x509"
)

func GetSystemCertPool() (*x509.CertPool, error) {
	return x509.SystemCertPool()
}
