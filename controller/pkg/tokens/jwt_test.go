package tokens

import (
	"crypto/ecdsa"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/crypto"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	tags = policy.NewTagStoreFromMap(map[string]string{
		"label1": "value1",
		"label2": "value2",
	})

	rmt           = "1234567890123456"
	lcl           = "098765432109876"
	defaultClaims = ConnectionClaims{
		T:   tags,
		RMT: []byte(rmt),
		EK:  []byte{},
	}

	ackClaims = ConnectionClaims{
		T:   nil,
		RMT: []byte(rmt),
		LCL: []byte(lcl),
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
	Convey("Given that I instantiate a new JWT Engine with max server name that violates requirements, it should fail", t, func() {
		secrets := secrets.NewPSKSecrets(psk)
		_, err := NewJWT(validity, "0123456789012345678901234567890123456789", secrets)
		So(err, ShouldNotBeNil)
	})

	Convey("Given that I instantiate a new JWT Engine with nil secrets, it should fail", t, func() {
		_, err := NewJWT(validity, "TEST", nil)
		So(err, ShouldNotBeNil)
	})

	Convey("Given that I instantiate a new JWT Engine with shared secrets, it should succeed", t, func() {

		j := &JWTConfig{}
		scrts := secrets.NewPSKSecrets(psk)
		jwtConfig, _ := NewJWT(validity, "TRIREME", scrts)

		So(jwtConfig, ShouldHaveSameTypeAs, j)
		So(jwtConfig.Issuer, ShouldResemble, "TRIREME                 ")
		So(jwtConfig.ValidityPeriod.Seconds(), ShouldEqual, validity.Seconds())
		So(jwtConfig.signMethod, ShouldEqual, jwt.SigningMethodHS256)
	})

	Convey("Given that I instantiate a new JWT Engine with PKI secrets, it should succeed", t, func() {

		j := &JWTConfig{}
		scrts, serr := secrets.NewPKISecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool), nil)
		So(serr, ShouldBeNil)
		jwtConfig, _ := NewJWT(validity, "TRIREME", scrts)

		So(jwtConfig, ShouldHaveSameTypeAs, j)
		So(jwtConfig.Issuer, ShouldResemble, "TRIREME                 ")
		So(jwtConfig.ValidityPeriod.Seconds(), ShouldEqual, validity.Seconds())
		So(jwtConfig.signMethod, ShouldEqual, jwt.SigningMethodES256)
	})

	Convey("Given that I instantiate a new JWT null encryption, it should succeed", t, func() {

		j := &JWTConfig{}
		scrts, err := secrets.NewNullPKI([]byte(keyPEM), []byte(certPEM), []byte(caPool))
		So(err, ShouldBeNil)
		jwtConfig, _ := NewJWT(validity, "TRIREME", scrts)

		So(jwtConfig, ShouldHaveSameTypeAs, j)
		So(jwtConfig.Issuer, ShouldResemble, "TRIREME                 ")
		So(jwtConfig.ValidityPeriod.Seconds(), ShouldEqual, validity.Seconds())
		So(jwtConfig.signMethod, ShouldEqual, jwt.SigningMethodNone)
	})

}

func TestCreateAndVerifyPSK(t *testing.T) {
	Convey("Given a JWT valid engine with pre-shared key ", t, func() {
		scrts := secrets.NewPSKSecrets(psk)
		jwtConfig, _ := NewJWT(validity, "TRIREME", scrts)
		nonce := []byte("1234567890123456")
		Convey("Given a signature request for a normal packet", func() {
			token, err1 := jwtConfig.CreateAndSign(false, &defaultClaims, nonce)
			recoveredClaims, recoveredNonce, _, err2 := jwtConfig.Decode(false, token, nil)

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(recoveredClaims, ShouldNotBeNil)
			lclaims, ok1 := recoveredClaims.T.Get("label1")
			dclaims, ok2 := recoveredClaims.T.Get("label1")
			So(ok1, ShouldBeTrue)
			So(ok2, ShouldBeTrue)
			So(lclaims, ShouldResemble, dclaims)
			So(string(recoveredClaims.RMT), ShouldEqual, rmt)
			So(recoveredNonce, ShouldResemble, nonce)
		})

		Convey("Given a signature request for an ACK packet", func() {
			token, err1 := jwtConfig.CreateAndSign(true, &ackClaims, nonce)
			recoveredClaims, _, _, err2 := jwtConfig.Decode(true, token, nil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(recoveredClaims, ShouldNotBeNil)
			So(recoveredClaims.RMT, ShouldResemble, []byte(rmt))
			So(recoveredClaims.LCL, ShouldResemble, []byte(lcl))
			So(recoveredClaims.T, ShouldBeNil)
		})

		Convey("Given a signature request with a bad packet ", func() {
			recoveredClaims, _, _, err := jwtConfig.Decode(false, nil, nil)
			So(err, ShouldNotBeNil)
			So(recoveredClaims, ShouldBeNil)
		})

	})
}

func TestCreateAndVerifyPKI(t *testing.T) {
	Convey("Given a JWT valid engine with a PKI  key ", t, func() {
		scrts, serr := secrets.NewPKISecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool), nil)
		So(serr, ShouldBeNil)
		jwtConfig, _ := NewJWT(validity, "TRIREME", scrts)
		_, cert, _, _ := crypto.LoadAndVerifyECSecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool))

		nonce := []byte("1234567890123456")
		Convey("Given a signature request for a normal packet", func() {
			token, err1 := jwtConfig.CreateAndSign(false, &defaultClaims, nonce)
			recoveredClaims, recoveredNonce, key, err2 := jwtConfig.Decode(false, token, nil)

			So(err2, ShouldBeNil)
			So(err1, ShouldBeNil)
			So(recoveredClaims, ShouldNotBeNil)
			lclaims, ok1 := recoveredClaims.T.Get("label1")
			dclaims, ok2 := recoveredClaims.T.Get("label1")
			So(ok1, ShouldBeTrue)
			So(ok2, ShouldBeTrue)
			So(lclaims, ShouldResemble, dclaims)
			So(string(recoveredClaims.RMT), ShouldEqual, rmt)
			So(string(recoveredClaims.LCL), ShouldEqual, "")
			So(nonce, ShouldResemble, recoveredNonce)
			So(cert, ShouldResemble, key)
		})

		Convey("Given a signature request that hits the cache ", func() {
			token1, err1 := jwtConfig.CreateAndSign(false, &defaultClaims, nonce)
			recoveredClaims1, recoveredNonce1, key1, err2 := jwtConfig.Decode(false, token1, nil)
			nonce2 := []byte("9876543210123456")
			err3 := jwtConfig.Randomize(token1, nonce2)
			recoveredClaims2, recoveredNonce2, key2, err4 := jwtConfig.Decode(false, token1, nil)

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(err3, ShouldBeNil)
			So(err4, ShouldBeNil)
			So(recoveredClaims1, ShouldNotBeNil)
			So(recoveredClaims2, ShouldNotBeNil)
			lclaims1, ok1 := recoveredClaims1.T.Get("label1")
			dclaims1, ok2 := recoveredClaims1.T.Get("label1")
			So(ok1, ShouldBeTrue)
			So(ok2, ShouldBeTrue)
			So(lclaims1, ShouldResemble, dclaims1)
			lclaims2, ok3 := recoveredClaims2.T.Get("label1")
			dclaims2, ok4 := recoveredClaims2.T.Get("label1")
			So(ok3, ShouldBeTrue)
			So(ok4, ShouldBeTrue)
			So(lclaims2, ShouldResemble, dclaims2)
			So(string(recoveredClaims1.RMT), ShouldEqual, rmt)
			So(string(recoveredClaims1.LCL), ShouldEqual, "")
			So(string(recoveredClaims2.RMT), ShouldEqual, rmt)
			So(string(recoveredClaims2.LCL), ShouldEqual, "")
			So(nonce, ShouldResemble, recoveredNonce1)
			So(nonce2, ShouldResemble, recoveredNonce2)
			So(cert, ShouldResemble, key1)
			So(cert, ShouldResemble, key2)
		})

		Convey("Given a signature request for an ACK packet", func() {
			token, err1 := jwtConfig.CreateAndSign(true, &ackClaims, nonce)
			recoveredClaims, _, _, err2 := jwtConfig.Decode(true, token, cert.PublicKey.(*ecdsa.PublicKey))

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(recoveredClaims, ShouldNotBeNil)
			So(string(recoveredClaims.RMT), ShouldEqual, rmt)
			So(string(recoveredClaims.LCL), ShouldEqual, lcl)
			So(recoveredClaims.T, ShouldBeNil)
		})
	})
}

func TestNegativeConditions(t *testing.T) {
	Convey("Given a JWT valid engine with a PKI  key ", t, func() {
		scrts, serr := secrets.NewPKISecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool), nil)
		So(serr, ShouldBeNil)
		jwtConfig, _ := NewJWT(validity, "TRIREME", scrts)
		nonce := []byte("012456789123456")
		Convey("Test a token with a bad length ", func() {
			token, err1 := jwtConfig.CreateAndSign(false, &defaultClaims, nonce)
			_, _, _, err2 := jwtConfig.Decode(false, token[:len(token)-len(certPEM)-1], nil)
			So(err2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
		})

		Convey("Test a token with a bad public key", func() {
			token, err1 := jwtConfig.CreateAndSign(false, &defaultClaims, nonce)
			So(err1, ShouldBeNil)
			token[len(token)-1] = 0
			token[len(token)-2] = 0
			token[len(token)-3] = 0
			token[len(token)-4] = 0
			_, _, _, err2 := jwtConfig.Decode(false, token, nil)
			So(err2, ShouldNotBeNil)
		})

		Convey("Test an ack token with a bad key", func() {
			token, err1 := jwtConfig.CreateAndSign(false, &ackClaims, nonce)

			_, _, _, err2 := jwtConfig.Decode(true, token, certPEM[:10])
			So(err2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
		})

	})
}

func TestRamdomize(t *testing.T) {
	Convey("Given a token engine with PKI key and a good token", t, func() {
		nonce := []byte("012456789123456")
		scrts, serr := secrets.NewPKISecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool), nil)
		So(serr, ShouldBeNil)
		jwtConfig, _ := NewJWT(validity, "TRIREME", scrts)
		token, err := jwtConfig.CreateAndSign(false, &defaultClaims, nonce)
		So(err, ShouldBeNil)

		newNonce := []byte("9876543219123456")
		Convey("I should get a new random nonce", func() {
			err := jwtConfig.Randomize(token, newNonce)
			So(err, ShouldBeNil)
		})

		Convey("I should an error if the token is short ", func() {
			err := jwtConfig.Randomize(token[:noncePosition+NonceLength-1], nonce)
			So(err, ShouldNotBeNil)
		})

	})
}

func TestRetrieveNonce(t *testing.T) {
	Convey("Given a token engine and a good token", t, func() {
		scrts, serr := secrets.NewPKISecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool), nil)
		So(serr, ShouldBeNil)
		jwtConfig, _ := NewJWT(validity, "TRIREME", scrts)
		nonce := []byte("0124567890123456")
		token, err := jwtConfig.CreateAndSign(false, &defaultClaims, nonce)
		So(err, ShouldBeNil)
		Convey("When I try to get the nonce of the token, I should get the right value", func() {
			tokenNonce, err := jwtConfig.RetrieveNonce(token)
			So(err, ShouldBeNil)
			So(tokenNonce, ShouldResemble, nonce)
		})

		Convey("When I try to get the nonce of bad token, I should get an error", func() {
			_, err := jwtConfig.RetrieveNonce(token[:2])
			So(err, ShouldNotBeNil)
		})
	})
}
