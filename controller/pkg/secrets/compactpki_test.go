package secrets

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/trireme-lib/utils/crypto"

	. "github.com/smartystreets/goconvey/convey"
)

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
	token, err := p.CreateTokenFromCertificate(clientCert)
	if err != nil {
		panic("can't create token")
	}
	return token
}

func TestNewCompactPKI(t *testing.T) {
	txKey := createTxtToken()
	// txkey is a token that has the client public key signed by the CA
	Convey("When I create a new compact PKI, it should succeed ", t, func() {

		p, err := NewCompactPKI([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM), txKey, constants.CompressionTypeNone)
		So(err, ShouldBeNil)
		So(p, ShouldNotBeNil)
		So(p.AuthorityPEM, ShouldResemble, []byte(caPEM))
		So(p.PrivateKeyPEM, ShouldResemble, []byte(privateKeyPEM))
		So(p.PublicKeyPEM, ShouldResemble, []byte(publicPEM))
	})

	Convey("When I create a new compact PKI with invalid certs, it should fail", t, func() {
		p, err := NewCompactPKI([]byte(privateKeyPEM)[:20], []byte(publicPEM)[:30], []byte(caPEM), txKey, constants.CompressionTypeNone)
		So(err, ShouldNotBeNil)
		So(p, ShouldBeNil)
	})

	Convey("When I create a new compact PKI with invalid CA, it should fail", t, func() {
		p, err := NewCompactPKI([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM)[:10], txKey, constants.CompressionTypeNone)
		So(err, ShouldNotBeNil)
		So(p, ShouldBeNil)
	})

}

func TestBasicInterfaceFunctions(t *testing.T) {
	txKey := createTxtToken()
	Convey("Given a valid CompactPKI ", t, func() {
		p, err := NewCompactPKI([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM), txKey, constants.CompressionTypeNone)
		So(err, ShouldBeNil)
		So(p, ShouldNotBeNil)

		key, cert, _, _ := crypto.LoadAndVerifyECSecrets([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM))
		Convey("I should get the right secrets type ", func() {
			So(p.Type(), ShouldResemble, PKICompactType)
		})

		Convey("I should get the right encoding key", func() {
			So(*(p.EncodingKey().(*ecdsa.PrivateKey)), ShouldResemble, *key)
		})

		Convey("I should get the right transmitter key", func() {
			So(p.TransmittedKey(), ShouldResemble, txKey)
		})

		Convey("I should get the right CA Auth PEM file", func() {
			So(p.AuthPEM(), ShouldResemble, []byte(caPEM))
		})

		Convey("I should get the right Certificate PEM", func() {
			So(p.TransmittedPEM(), ShouldResemble, []byte(publicPEM))
		})

		Convey("I Should get the right Key PEM", func() {
			So(p.EncodingPEM(), ShouldResemble, []byte(privateKeyPEM))
		})

		Convey("I should ge the right ack size", func() {
			So(p.AckSize(), ShouldEqual, 280)
		})

		Convey("I should get the right public key, ", func() {
			So(p.PublicKey().(*x509.Certificate), ShouldResemble, cert)
		})

		Convey("When I verify the received public key, it should succeed", func() {
			pk, err := p.VerifyPublicKey(txKey)
			So(err, ShouldBeNil)
			So(pk.(*ecdsa.PublicKey), ShouldResemble, cert.PublicKey.(*ecdsa.PublicKey))
		})

		Convey("When I try to get the decoding key when the ack key is nil", func() {
			key, err := p.DecodingKey("server", nil, txKey)
			So(err, ShouldBeNil)
			So(key, ShouldResemble, txKey)
		})

		Convey("When I try to get the decoding key with the ack", func() {
			key, err := p.DecodingKey("server", cert.PublicKey, nil)
			So(err, ShouldBeNil)
			So(key.(*ecdsa.PublicKey), ShouldResemble, cert.PublicKey.(*ecdsa.PublicKey))
		})

		Convey("When I try to get the decoding key and both inputs are nil, I should get an error ", func() {
			_, err := p.DecodingKey("server", nil, nil)
			So(err, ShouldNotBeNil)
		})
	})
}
