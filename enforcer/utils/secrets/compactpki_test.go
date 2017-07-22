package secrets

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"github.com/aporeto-inc/trireme/crypto"
	"github.com/aporeto-inc/trireme/enforcer/utils/pkiverifier"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	caPEM = `-----BEGIN CERTIFICATE-----
MIIB9jCCAZ2gAwIBAgIJAJTgLK9oj4fKMAoGCCqGSM49BAMDMFgxCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJDQTERMA8GA1UEBwwIU2FuIEpvc2UxEDAOBgNVBAoMB0Fw
b3JldG8xFzAVBgNVBAMMDmFwb211eC5wcml2YXRlMB4XDTE3MDQzMDE1NTgyNFoX
DTI3MDQyODE1NTgyNFowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMREwDwYD
VQQHDAhTYW4gSm9zZTEQMA4GA1UECgwHQXBvcmV0bzEXMBUGA1UEAwwOYXBvbXV4
LnByaXZhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATVcrrOIlMO/ty7cgCI
YTeUcYY9nPiLdbEcQI5rT9vxoQ6wIIeUeO61TvSKXIa5s1qgJNnVnerfPIgKxQ/y
q9KGo1AwTjAdBgNVHQ4EFgQUcJHVuZ7plgh4yj+qRwDSKwDJBmMwHwYDVR0jBBgw
FoAUcJHVuZ7plgh4yj+qRwDSKwDJBmMwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQD
AwNHADBEAiBivt359l723AELpmTKnGtnUCtnHCLUGwX1jMaYaVp+uwIgGEfM6d50
RS0FNXCgNPdSLl6wTSLdZnVG+SXLnNNvb5g=
-----END CERTIFICATE-----`
	caKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ/aEmqa3eFqVbs2ITHAsEJpSjeeZhQUk+20gwmXmQbIoAoGCCqGSM49
AwEHoUQDQgAE1XK6ziJTDv7cu3IAiGE3lHGGPZz4i3WxHECOa0/b8aEOsCCHlHju
tU70ilyGubNaoCTZ1Z3q3zyICsUP8qvShg==
-----END EC PRIVATE KEY-----`
	privateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJHanaD9zGLPe/XdkA7fj7ocRFK7x7yun3299Gv/eIFroAoGCCqGSM49
AwEHoUQDQgAEKsTNnVOtYN1LbVQssEuRx+Y+Jj2tz5wV8H36OzhD2aEZzVfgUPgB
9P8vQrXLSwrhwx0lUCegBVNyfnIjDFuhew==
-----END EC PRIVATE KEY-----`
	publicPEM = `-----BEGIN CERTIFICATE-----
MIICLjCCAdSgAwIBAgIRAJHHS9iyyJ3zFt30H1bcfOowCgYIKoZIzj0EAwIwWDEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMREwDwYDVQQHDAhTYW4gSm9zZTEQMA4G
A1UECgwHQXBvcmV0bzEXMBUGA1UEAwwOYXBvbXV4LnByaXZhdGUwHhcNMTcwNDMw
MjA1NTUzWhcNMTgwNDMwMjA1NTUzWjBYMQ8wDQYDVQQKEwZzeXN0ZW0xGjAYBgNV
BAsTEWFwb3JldG8tZW5mb3JjZXJkMSkwJwYDVQQDDCA1OTA2NGY1OTcxMGJkMDQ4
MjEzYjFiMzdAL2Fwb211eDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCrEzZ1T
rWDdS21ULLBLkcfmPiY9rc+cFfB9+js4Q9mhGc1X4FD4AfT/L0K1y0sK4cMdJVAn
oAVTcn5yIwxboXujfzB9MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAM
BgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFHCR1bme6ZYIeMo/qkcA0isAyQZjMC0G
A1UdEQQmMCSCEGFwb211eC1lbmZvcmNlcmSBEGFwb211eC1lbmZvcmNlcmQwCgYI
KoZIzj0EAwIDSAAwRQIgLyFySAkpi0Tk3mKiExAxVHmB2ub6N3Nb9qXAwwlqCYcC
IQC9S/1lG5UDOC4sgnK/atyU3AWoUHsyeV8UTS/uY8p/Ag==
-----END CERTIFICATE-----`
)

func createTxtToken() []byte {
	caKey, err := crypto.LoadEllipticCurveKey([]byte(caKeyPEM))
	if err != nil {
		panic("bad ca key ")
	}
	caCert, err := crypto.LoadCertificate([]byte(caPEM))
	if err != nil {
		panic("bad ca cert")
	}

	clientCert, err := crypto.LoadCertificate([]byte(publicPEM))
	if err != nil {
		panic("bad client cert ")
	}

	p := pkiverifier.NewConfig(caCert.PublicKey.(*ecdsa.PublicKey), caKey, -1)
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

		p, err := NewCompactPKI([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM), txKey)
		So(err, ShouldBeNil)
		So(p, ShouldNotBeNil)
		So(p.AuthorityPEM, ShouldResemble, []byte(caPEM))
		So(p.PrivateKeyPEM, ShouldResemble, []byte(privateKeyPEM))
		So(p.PublicKeyPEM, ShouldResemble, []byte(publicPEM))
	})

	Convey("When I create a new compact PKI with invalid certs, it should fail", t, func() {
		p, err := NewCompactPKI([]byte(privateKeyPEM)[:20], []byte(publicPEM)[:30], []byte(caPEM), txKey)
		So(err, ShouldNotBeNil)
		So(p, ShouldBeNil)
	})

	Convey("When I create a new compact PKI with invalid CA, it should fail", t, func() {
		p, err := NewCompactPKI([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM)[:10], txKey)
		So(err, ShouldNotBeNil)
		So(p, ShouldBeNil)
	})

}

func TestBasicInterfaceFunctions(t *testing.T) {
	txKey := createTxtToken()
	Convey("Given a valid CompactPKI ", t, func() {
		p, err := NewCompactPKI([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM), txKey)
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
			So(p.AckSize(), ShouldEqual, 322)
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
