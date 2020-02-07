package windowscertbug

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// Some background: https://github.com/golang/go/issues/34937
// The below routines work around golang's windows certificate shortcomings.
// For all these routines NOTE that their usage assumes that all system roots
// are included.

// VerifyCertificate will call Verify twice if needed, to ensure
// the Windows root store is completely checked.
func VerifyCertificate(cert *x509.Certificate, opts x509.VerifyOptions) (chains [][]*x509.Certificate, err error) {
	if opts.Roots != nil {
		if chains, err := cert.Verify(opts); err == nil {
			return chains, err
		}
		// the given roots did not work, so now try Verify with nil Roots
		opts.Roots = nil
	}
	return cert.Verify(opts)
}

// PrepareClientTLSConfig will modify the given tls.Config so that
// it does custom cert verification on Windows to workaround a golang bug.
func PrepareClientTLSConfig(config *tls.Config) *tls.Config {
	if config.InsecureSkipVerify {
		return config
	}
	if config.RootCAs == nil {
		return config
	}
	config.InsecureSkipVerify = true
	config.VerifyPeerCertificate = makeVerifyPeer(config, false)
	return config
}

// PrepareServerTLSConfig will modify the given tls.Config so that
// it does custom cert verification on Windows to workaround a golang bug.
func PrepareServerTLSConfig(config *tls.Config) *tls.Config {
	if config.InsecureSkipVerify {
		return config
	}
	if config.ClientAuth < tls.VerifyClientCertIfGiven {
		return config
	}
	if config.ClientCAs == nil {
		return config
	}
	config.InsecureSkipVerify = true
	config.VerifyPeerCertificate = makeVerifyPeer(config, true)
	return config
}

// return a custom VerifyPeerCertificate func
// this is based on https://tip.golang.org/pkg/crypto/tls/#example_Config_verifyPeerCertificate
func makeVerifyPeer(tlsConfig *tls.Config, asServer bool) func([][]byte, [][]*x509.Certificate) error {
	return func(certificates [][]byte, _ [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, len(certificates))
		for i, asn1Data := range certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}
			certs[i] = cert
		}

		opts := x509.VerifyOptions{
			Roots:         tlsConfig.RootCAs,
			DNSName:       tlsConfig.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		if asServer {
			opts.Roots = tlsConfig.ClientCAs
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		if opts.DNSName == "" && len(certs[0].DNSNames) > 0 {
			opts.DNSName = certs[0].DNSNames[0]
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := VerifyCertificate(certs[0], opts)
		return err
	}
}
