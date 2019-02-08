package secrets

import (
	"crypto/x509"

	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/trireme-lib/utils/crypto"
)

// Certs
var (
	CAPEM = `-----BEGIN CERTIFICATE-----
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
	CAKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILpUWKqL6Sr+HrKDKLHt/vN6EYi22rJKV2q9xgKmiCqioAoGCCqGSM49
AwEHoUQDQgAEHKTpuFQFsjXCOP1mT6o/RAbuV1kKachti6F1WDb9WAnyQRWLlREc
VWmRHFCdHHhP3aBcqYUtTocN0I6g0MWpHg==
-----END EC PRIVATE KEY-----`
	PrivateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGx017ukBSUSddLXefL/5nxxaRXuM1H/tUxQAYxWBrQtoAoGCCqGSM49
AwEHoUQDQgAEZKBbcTmg0hGyVcgsUH7xijvaNOJ3EPM3Oq08VdCBsPNAojAR9wfX
KLO/w0SRKj1DL03a9dl1Gwk0r7F0VnPQyw==
-----END EC PRIVATE KEY-----`
	PublicPEM = `-----BEGIN CERTIFICATE-----
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

// CreateTxtToken creates a transmitter token
func CreateTxtToken() []byte {
	caKey, err := crypto.LoadEllipticCurveKey([]byte(CAKeyPEM))
	if err != nil {
		panic("bad ca key ")
	}

	clientCert, err := crypto.LoadCertificate([]byte(PublicPEM))
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

// CreateCompactPKITestSecrets creates test secrets
func CreateCompactPKITestSecrets() (*x509.Certificate, Secrets, error) {
	txtKey, err := crypto.LoadEllipticCurveKey([]byte(PrivateKeyPEM))
	if err != nil {
		return nil, nil, err
	}

	cert, err := crypto.LoadCertificate([]byte(PublicPEM))
	if err != nil {
		return nil, nil, err
	}

	issuer := pkiverifier.NewPKIIssuer(txtKey)
	txtToken, err := issuer.CreateTokenFromCertificate(cert, []string{})
	if err != nil {
		return nil, nil, err
	}

	scrts, err := NewCompactPKIWithTokenCA([]byte(PrivateKeyPEM), []byte(PublicPEM), []byte(CAPEM), [][]byte{[]byte(PublicPEM)}, txtToken, claimsheader.CompressionTypeNone)
	if err != nil {
		return nil, nil, err
	}

	return cert, scrts, nil
}
