package tokens

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/aporeto-inc/trireme/cryptofunctions"
	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	tags = map[string]string{
		"label1": "value1",
		"label2": "value2",
	}

	lcl           = "09876543210987654321098765432109"
	rmt           = "12345678901234567890123456789012"
	defaultClaims = ConnectionClaims{
		T:   tags,
		LCL: []byte(lcl),
		RMT: []byte(rmt),
		EK:  []byte{},
	}

	ackClaims = ConnectionClaims{
		T:   nil,
		LCL: []byte(lcl),
		RMT: []byte(rmt),
		EK:  []byte{},
	}
	validity = time.Second * 10
	psk      = []byte("I NEED A BETTER KEY")

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

// TestConstructorNewPolicyDB tests the NewPolicyDB constructor
func TestConstructorNewJWT(t *testing.T) {
	Convey("Given that I instantiate a new JWT Engine with shared secrets, it should succeed", t, func() {

		j := &JWTConfig{}
		secrets := NewPSKSecrets(psk)
		jwtConfig := NewJWT(validity, "TRIREME", secrets)

		So(jwtConfig, ShouldHaveSameTypeAs, j)
		So(jwtConfig.Issuer, ShouldResemble, "TRIREME                             ")
		So(jwtConfig.ValidityPeriod.Seconds(), ShouldEqual, validity.Seconds())
		So(jwtConfig.signMethod, ShouldEqual, jwt.SigningMethodHS256)
	})

	Convey("Given that I instantiate a new JWT Engine with PKI secrets, it should succeed", t, func() {

		j := &JWTConfig{}
		secrets := NewPKISecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool), nil)
		jwtConfig := NewJWT(validity, "TRIREME", secrets)

		So(jwtConfig, ShouldHaveSameTypeAs, j)
		So(jwtConfig.Issuer, ShouldResemble, "TRIREME                             ")
		So(jwtConfig.ValidityPeriod.Seconds(), ShouldEqual, validity.Seconds())
		So(jwtConfig.signMethod, ShouldEqual, jwt.SigningMethodES256)
	})

}

func TestCreateAndVerifyPSK(t *testing.T) {
	Convey("Given a JWT valid engine with pre-shared key ", t, func() {
		secrets := NewPSKSecrets(psk)
		jwtConfig := NewJWT(validity, "TRIREME", secrets)

		Convey("Given a signature request for a normal packet", func() {
			token := jwtConfig.CreateAndSign(false, &defaultClaims)
			recoveredClaims, _ := jwtConfig.Decode(false, token, nil)

			So(recoveredClaims, ShouldNotBeNil)
			So(recoveredClaims.T["label1"], ShouldEqual, defaultClaims.T["label1"])
			So(recoveredClaims.T["label2"], ShouldEqual, defaultClaims.T["label2"])
			So(string(recoveredClaims.RMT), ShouldEqual, rmt)
			So(string(recoveredClaims.LCL), ShouldEqual, lcl)
		})

		Convey("Given a singature request for an ACK packet", func() {
			token := jwtConfig.CreateAndSign(true, &ackClaims)
			recoveredClaims, _ := jwtConfig.Decode(true, token, nil)

			So(recoveredClaims, ShouldNotBeNil)
			So(string(recoveredClaims.RMT), ShouldEqual, rmt)
			So(string(recoveredClaims.LCL), ShouldEqual, lcl)
			So(recoveredClaims.T, ShouldBeNil)

		})

		Convey("Given a singature request with a bad packet ", func() {
			recoveredClaims, _ := jwtConfig.Decode(false, nil, nil)

			So(recoveredClaims, ShouldBeNil)

		})

	})
}

func TestCreateAndVerifyPKI(t *testing.T) {
	Convey("Given a JWT valid engine with a PKI  key ", t, func() {
		secrets := NewPKISecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool), nil)
		jwtConfig := NewJWT(validity, "TRIREME", secrets)
		_, cert, _, _ := cryptofunctions.LoadAndVerifyECSecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool))

		Convey("Given a signature request for a normal packet", func() {
			token := jwtConfig.CreateAndSign(false, &defaultClaims)
			recoveredClaims, _ := jwtConfig.Decode(false, token, nil)

			So(recoveredClaims, ShouldNotBeNil)
			So(recoveredClaims.T["label1"], ShouldEqual, defaultClaims.T["label1"])
			So(recoveredClaims.T["label2"], ShouldEqual, defaultClaims.T["label2"])
			So(string(recoveredClaims.RMT), ShouldEqual, rmt)
			So(string(recoveredClaims.LCL), ShouldEqual, lcl)
		})

		Convey("Given a singature request for an ACK packet", func() {
			token := jwtConfig.CreateAndSign(true, &ackClaims)
			recoveredClaims, _ := jwtConfig.Decode(true, token, cert.PublicKey.(*ecdsa.PublicKey))

			So(recoveredClaims, ShouldNotBeNil)
			So(string(recoveredClaims.RMT), ShouldEqual, rmt)
			So(string(recoveredClaims.LCL), ShouldEqual, lcl)
			So(recoveredClaims.T, ShouldBeNil)

		})

	})
}

//
//
// func TestCreateAndVerifyPKI(t *testing.T) {
// 	Convey("Given  a new JWT Engine with PKI and inband certificates", t, func() {
//
// 		jwtConfig := NewPKIJWT(validity, "TRIREME", nil, []byte(keyPEM), []byte(certPEM), []byte(caPool))
//
// 		Convey("Given a signature request for a normal packet ", func() {
// 			token := jwtConfig.CreateAndSign(false, &defaultClaims)
// 			recoveredClaims, cert := jwtConfig.Decode(false, token, nil)
//
// 			So(recoveredClaims, ShouldNotBeNil)
// 			So(recoveredClaims.T["label1"], ShouldEqual, defaultClaims.T["label1"])
// 			So(recoveredClaims.T["label2"], ShouldEqual, defaultClaims.T["label2"])
// 			So(string(recoveredClaims.RMT), ShouldEqual, rmt)
// 			So(string(recoveredClaims.LCL), ShouldEqual, lcl)
// 			So(cert, ShouldNotBeNil)
//
// 		})
//
// 		Convey("Given a singature request for an ACK packet, where there is no sign certificate", func() {
// 			token := jwtConfig.CreateAndSign(true, &ackClaims)
// 			recoveredClaims, _ := jwtConfig.Decode(true, token, nil)
//
// 			So(recoveredClaims, ShouldBeNil)
// 		})
//
// 		Convey("Given a signature request for an ack packet where the right certificate is provided", func() {
// 			_, cert, _, _ := loadKeys([]byte(keyPEM), []byte(certPEM), []byte(caPool))
// 			token := jwtConfig.CreateAndSign(true, &ackClaims)
// 			recoveredClaims, _ := jwtConfig.Decode(true, token, cert)
// 			So(recoveredClaims, ShouldNotBeNil)
// 		})
// 	})
//
// 	Convey("Given a token engine with out-of-band certificate generation", t, func() {
// 		_, cert, _, _ := loadKeys([]byte(keyPEM), []byte(certPEM), []byte(caPool))
//
// 		certCache := map[string]*ecdsa.PublicKey{
// 			"TRIREME": cert.PublicKey.(*ecdsa.PublicKey),
// 		}
//
// 		jwtConfig := NewPKIJWT(validity, "TRIREME", certCache, []byte(keyPEM), []byte(certPEM), []byte(caPool))
// 		So(jwtConfig.IncludeCert, ShouldBeFalse)
// 		So(jwtConfig.PublicKeyCache, ShouldEqual, certCache)
// 		So(jwtConfig.PublicKeyCache["TRIREME"], ShouldEqual, cert.PublicKey.(*ecdsa.PublicKey))
//
// 		Convey("Given a signature request for a normal packet ", func() {
// 			token := jwtConfig.CreateAndSign(false, &defaultClaims)
// 			recoveredClaims, _ := jwtConfig.Decode(false, token, nil)
//
// 			So(recoveredClaims, ShouldNotBeNil)
// 			So(recoveredClaims.T["label1"], ShouldEqual, defaultClaims.T["label1"])
// 			So(recoveredClaims.T["label2"], ShouldEqual, defaultClaims.T["label2"])
// 			So(string(recoveredClaims.RMT), ShouldEqual, rmt)
// 			So(string(recoveredClaims.LCL), ShouldEqual, lcl)
//
// 		})
//
// 		Convey("Given a signature request for a normal packet, where the cache doesn't have the certificate ", func() {
// 			token := jwtConfig.CreateAndSign(false, &defaultClaims)
// 			jwtConfig.PublicKeyCache = nil
// 			recoveredClaims, _ := jwtConfig.Decode(false, token, nil)
//
// 			So(recoveredClaims, ShouldBeNil)
//
// 		})
//
// 		Convey("Given a signature request for an ack packet where the right certificate is provided", func() {
// 			token := jwtConfig.CreateAndSign(true, &ackClaims)
// 			recoveredClaims, _ := jwtConfig.Decode(true, token, nil)
//
// 			So(recoveredClaims, ShouldNotBeNil)
// 		})
// 	})
//
// }
