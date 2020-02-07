// +build !windows

package windowscertbug

import (
	"crypto/tls"
	"crypto/x509"
)

// VerifyCertificate for platforms without the cert bug does not
// do anything special.
func VerifyCertificate(cert *x509.Certificate, opts x509.VerifyOptions) (chains [][]*x509.Certificate, err error) {
	return cert.Verify(opts)
}

// PrepareClientTLSConfig for platforms without the cert bug does not
// do anything special.
func PrepareClientTLSConfig(config *tls.Config) *tls.Config {
	return config
}

// PrepareServerTLSConfig for platforms without the cert bug does not
// do anything special.
func PrepareServerTLSConfig(config *tls.Config) *tls.Config {
	return config
}
