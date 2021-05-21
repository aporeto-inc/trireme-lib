package tlshelper

import "crypto/tls"

// The intent of this file is to provide secure base TLS configurations across all our proxies.

// TODO: This configuration can become limiting but thats what we support.
//   Feature: Users might want to add additional configs or alternatively
//            if the service is exposed, auto-discover them from the certificate
//            provided.

// NewBaseTLSClientConfig provides the generic base config to be used on a client.
func NewBaseTLSClientConfig() *tls.Config {

	return &tls.Config{
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
		// for now lets make it TLS1.2 as supported max Version.
		// TODO: Need to test before enabling TLS 1.3, currently TLS 1.3 doesn't work with envoy.
		MaxVersion: tls.VersionTLS12,
	}
}

// NewBaseTLSServerConfig provides the generic base config to be used on a server.
func NewBaseTLSServerConfig() *tls.Config {
	return &tls.Config{
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
		ClientAuth:               tls.VerifyClientCertIfGiven,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}
