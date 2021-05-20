package testhelper

import (
	"crypto/x509"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets/compactpki"
	"go.aporeto.io/enforcerd/trireme-lib/utils/crypto"
)

// **** ATTENTION ****
// This package is only to help other packages to do unit tests.
// It's a very valid question, why arent they using a mock !

// Certs
var (
	caPEM = `-----BEGIN CERTIFICATE-----
MIIBmzCCAUCgAwIBAgIRAIbf7tsXeg6vUJ2pe3WXzgwwCgYIKoZIzj0EAwIwPDEQ
MA4GA1UEChMHQXBvcmV0bzEPMA0GA1UECxMGYXBvbXV4MRcwFQYDVQQDEw5BcG9t
dXggUm9vdCBDQTAeFw0xODA1MDExODM3MjNaFw0yODAzMDkxODM3MjNaMDwxEDAO
BgNVBAoTB0Fwb3JldG8xDzANBgNVBAsTBmFwb211eDEXMBUGA1UEAxMOQXBvbXV4
IFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQcpOm4VAWyNcI4/WZP
qj9EBu5XWQppyG2LoXVYNv1YCfJBFYuVERxVaZEcUJ0ceE/doFyphS1Ohw3QjqDQ
xakeoyMwITAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO
PQQDAgNJADBGAiEA+OL+qkSyXwLu6P/75kXBPo8fFGvXyX2vYis0hUAyHJcCIQCn
86EFqkJDkeAguDEKvVtORcnxl+rAP924/PJAHLMh6Q==
-----END CERTIFICATE-----`
	caKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILpUWKqL6Sr+HrKDKLHt/vN6EYi22rJKV2q9xgKmiCqioAoGCCqGSM49
AwEHoUQDQgAEHKTpuFQFsjXCOP1mT6o/RAbuV1kKachti6F1WDb9WAnyQRWLlREc
VWmRHFCdHHhP3aBcqYUtTocN0I6g0MWpHg==
-----END EC PRIVATE KEY-----`
	privateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGx017ukBSUSddLXefL/5nxxaRXuM1H/tUxQAYxWBrQtoAoGCCqGSM49
AwEHoUQDQgAEZKBbcTmg0hGyVcgsUH7xijvaNOJ3EPM3Oq08VdCBsPNAojAR9wfX
KLO/w0SRKj1DL03a9dl1Gwk0r7F0VnPQyw==
-----END EC PRIVATE KEY-----`
	publicPEM = `-----BEGIN CERTIFICATE-----
MIIBsDCCAVagAwIBAgIRAOmitRugFU+nAhiGsp6fYOwwCgYIKoZIzj0EAwIwPDEQ
MA4GA1UEChMHQXBvcmV0bzEPMA0GA1UECxMGYXBvbXV4MRcwFQYDVQQDEw5BcG9t
dXggUm9vdCBDQTAeFw0xODA1MDExODQwMzFaFw0yODAzMDkxODQwMzFaMDYxETAP
BgNVBAoTCHNvbWUgb3JnMRIwEAYDVQQLEwlzb21lLXVuaXQxDTALBgNVBAMTBHRl
c3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARkoFtxOaDSEbJVyCxQfvGKO9o0
4ncQ8zc6rTxV0IGw80CiMBH3B9cos7/DRJEqPUMvTdr12XUbCTSvsXRWc9DLoz8w
PTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
MAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAwRQIgBNYmLdmHI2gKy2NqfSXn
MEDF56xWq7son2mcSePvLU8CIQCUxgYfDZDf067Y7vqLw1mWMlSnqECELnq7zel1
fXtpyA==
-----END CERTIFICATE-----`
)

// createTxtToken creates a transmitter token
func createTxtToken() []byte {
	caKey, err := crypto.LoadEllipticCurveKey([]byte(caKeyPEM))
	if err != nil {
		panic("bad ca key ")
	}

	clientCert, err := crypto.LoadCertificate([]byte(publicPEM))
	if err != nil {
		panic("bad client cert ")
	}

	p := pkiverifier.NewPKIIssuer(caKey)
	token, err := p.CreateTokenFromCertificate(clientCert, []string{})
	if err != nil {
		panic("can't create token")
	}
	return token
}

// NewTestCompactPKISecrets creates test secrets
func NewTestCompactPKISecrets() (*x509.Certificate, secrets.Secrets, error) {
	txtKey, err := crypto.LoadEllipticCurveKey([]byte(privateKeyPEM))
	if err != nil {
		return nil, nil, err
	}

	cert, err := crypto.LoadCertificate([]byte(publicPEM))
	if err != nil {
		return nil, nil, err
	}

	issuer := pkiverifier.NewPKIIssuer(txtKey)
	txtToken, err := issuer.CreateTokenFromCertificate(cert, []string{})
	if err != nil {
		return nil, nil, err
	}

	tokenKey := &secrets.ControllerInfo{
		PublicKey: []byte(publicPEM),
	}

	scrts, err := compactpki.NewCompactPKIWithTokenCA([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM), []*secrets.ControllerInfo{tokenKey}, txtToken, claimsheader.CompressionTypeV1)
	if err != nil {
		return nil, nil, err
	}

	return cert, scrts, nil
}
