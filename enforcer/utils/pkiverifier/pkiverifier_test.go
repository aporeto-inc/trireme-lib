package pkiverifier

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/aporeto-inc/trireme/crypto"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	keyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPkiHqtH372JJdAG/IxJlE1gv03cdwa8Lhg2b3m/HmbyoAoGCCqGSM49
AwEHoUQDQgAEAfAL+AfPj/DnxrU6tUkEyzEyCxnflOWxhouy1bdzhJ7vxMb1vQ31
8ZbW/WvMN/ojIXqXYrEpISoojznj46w64w==
-----END EC PRIVATE KEY-----`
	caPool = `-----BEGIN CERTIFICATE-----
MIIBhTCCASwCCQC8b53yGlcQazAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExDDAKBgNVBAcMA1NKQzEQMA4GA1UECgwHVHJpcmVtZTEPMA0G
A1UEAwwGdWJ1bnR1MB4XDTE2MDkyNzIyNDkwMFoXDTI2MDkyNTIyNDkwMFowSzEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQwwCgYDVQQHDANTSkMxEDAOBgNVBAoM
B1RyaXJlbWUxDzANBgNVBAMMBnVidW50dTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABJxneTUqhbtgEIwpKUUzwz3h92SqcOdIw3mfQkMjg3Vobvr6JKlpXYe9xhsN
rygJmLhMAN9gjF9qM9ybdbe+m3owCgYIKoZIzj0EAwIDRwAwRAIgC1fVMqdBy/o3
jNUje/Hx0fZF9VDyUK4ld+K/wF3QdK4CID1ONj/Kqinrq2OpjYdkgIjEPuXoOoR1
tCym8dnq4wtH
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB3jCCAYOgAwIBAgIJALsW7pyC2ERQMAoGCCqGSM49BAMCMEsxCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJDQTEMMAoGA1UEBwwDU0pDMRAwDgYDVQQKDAdUcmlyZW1l
MQ8wDQYDVQQDDAZ1YnVudHUwHhcNMTYwOTI3MjI0OTAwWhcNMjYwOTI1MjI0OTAw
WjBLMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExDDAKBgNVBAcMA1NKQzEQMA4G
A1UECgwHVHJpcmVtZTEPMA0GA1UEAwwGdWJ1bnR1MFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAE4c2Fd7XeIB1Vfs51fWwREfLLDa55J+NBalV12CH7YEAnEXjl47aV
cmNqcAtdMUpf2oz9nFVI81bgO+OSudr3CqNQME4wHQYDVR0OBBYEFOBftuI09mmu
rXjqDyIta1gT8lqvMB8GA1UdIwQYMBaAFOBftuI09mmurXjqDyIta1gT8lqvMAwG
A1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAMylAHhbFA0KqhXIFiXNpEbH
JKaELL6UXXdeQ5yup8q+AiEAh5laB9rbgTymjaANcZ2YzEZH4VFS3CKoSdVqgnwC
dW4=
-----END CERTIFICATE-----`

	certPEM = `-----BEGIN CERTIFICATE-----
MIIBhjCCASwCCQCPCdgp39gHJTAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExDDAKBgNVBAcMA1NKQzEQMA4GA1UECgwHVHJpcmVtZTEPMA0G
A1UEAwwGdWJ1bnR1MB4XDTE2MDkyNzIyNDkwMFoXDTI2MDkyNTIyNDkwMFowSzEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQwwCgYDVQQHDANTSkMxEDAOBgNVBAoM
B1RyaXJlbWUxDzANBgNVBAMMBnVidW50dTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABAHwC/gHz4/w58a1OrVJBMsxMgsZ35TlsYaLstW3c4Se78TG9b0N9fGW1v1r
zDf6IyF6l2KxKSEqKI854+OsOuMwCgYIKoZIzj0EAwIDSAAwRQIgQwQn0jnK/XvD
KxgQd/0pW5FOAaB41cMcw4/XVlphO1oCIQDlGie+WlOMjCzrV0Xz+XqIIi1pIgPT
IG7Nv+YlTVp5qA==
-----END CERTIFICATE-----`
)

func TestNewConfig(t *testing.T) {
	Convey("When I create a new PKI configuration", t, func() {
		key, cert, _, err := crypto.LoadAndVerifyECSecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool))
		So(err, ShouldBeNil)
		Convey("When I use  valid keys, it should succeed ", func() {
			p := NewConfig(cert.PublicKey.(*ecdsa.PublicKey), key, -1)
			So(p, ShouldNotBeNil)
			So(p.validity, ShouldEqual, defaultValidity*time.Second)
			So(p.privateKey, ShouldEqual, key)
			So(p.publicKey, ShouldEqual, cert.PublicKey.(*ecdsa.PublicKey))
		})

		Convey("When I create a verifier with a custom validity, it should succeed  ", func() {
			p := NewConfig(cert.PublicKey.(*ecdsa.PublicKey), key, 10*time.Second)
			So(p, ShouldNotBeNil)
			So(p.validity, ShouldEqual, 10*time.Second)
			So(p.privateKey, ShouldEqual, key)
			So(p.publicKey, ShouldEqual, cert.PublicKey.(*ecdsa.PublicKey))
		})
	})
}

func TestCreateAndVerify(t *testing.T) {
	Convey("Given a valid verifier", t, func() {
		key, cert, _, err := crypto.LoadAndVerifyECSecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool))
		So(err, ShouldBeNil)
		p := NewConfig(cert.PublicKey.(*ecdsa.PublicKey), key, -1)
		So(p, ShouldNotBeNil)
		Convey("When I create a token", func() {
			token, err1 := p.CreateTokenFromCertificate(cert)
			So(err1, ShouldBeNil)
			rxtoken, err2 := p.Verify(token)
			So(err2, ShouldBeNil)
			So(*rxtoken.X, ShouldResemble, *cert.PublicKey.(*ecdsa.PublicKey).X)
			So(*rxtoken.Y, ShouldResemble, *cert.PublicKey.(*ecdsa.PublicKey).Y)
			So(rxtoken.Curve, ShouldResemble, cert.PublicKey.(*ecdsa.PublicKey).Curve)
		})
	})

	Convey("Given a valid verifier", t, func() {
		key, cert, _, err := crypto.LoadAndVerifyECSecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool))
		So(err, ShouldBeNil)
		p := NewConfig(cert.PublicKey.(*ecdsa.PublicKey), key, -1)
		So(p, ShouldNotBeNil)
		Convey("When I a receive a bad token, I should get an error", func() {
			token, err1 := p.CreateTokenFromCertificate(cert)
			So(err1, ShouldBeNil)
			token = token[:len(token)-10]
			_, err2 := p.Verify(token)
			So(err2, ShouldNotBeNil)
		})
	})
}

func TestCaching(t *testing.T) {
	Convey("Given a valid verifier with a zero timer for the cache", t, func() {
		key, cert, _, err := crypto.LoadAndVerifyECSecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool))
		So(err, ShouldBeNil)
		p := NewConfig(cert.PublicKey.(*ecdsa.PublicKey), key, 1*time.Second)
		So(p, ShouldNotBeNil)

		Convey("When I receive a token", func() {
			token, err1 := p.CreateTokenFromCertificate(cert)
			So(err1, ShouldBeNil)
			_, err2 := p.Verify(token)
			So(err2, ShouldBeNil)

			Convey("The cache should have the token ", func() {
				_, err := p.keycache.Get(string(token))
				So(err, ShouldBeNil)
				_, err2 := p.Verify(token)
				So(err2, ShouldBeNil)
			})

			Convey("The cache should not have the token after 2 seconds ", func() {
				time.Sleep(2 * time.Second)
				_, err := p.keycache.Get(string(token))
				So(err, ShouldNotBeNil)
			})
		})
	})
}
