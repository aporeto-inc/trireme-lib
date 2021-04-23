// +build !windows

package tokens

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"math/big"
	"reflect"
	"strconv"
	"testing"
	"time"

	enforcerconstants "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets/compactpki"
	"go.aporeto.io/enforcerd/trireme-lib/utils/crypto"
	"gotest.tools/assert"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

var (
	rmt       = "1234567890123456"
	lcl       = "098765432109876"
	bvalidity = time.Second * 10

	header = claimsheader.NewClaimsHeader(
		claimsheader.OptionCompressionType(claimsheader.CompressionTypeV1),
	)
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

func createCompactPKISecrets(tags []string) (secrets.Secrets, error) {
	txtKey, cert, _, err := crypto.LoadAndVerifyECSecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool))
	if err != nil {
		return nil, err
	}

	issuer := pkiverifier.NewPKIIssuer(txtKey)
	txtToken, err := issuer.CreateTokenFromCertificate(cert, tags)
	if err != nil {
		return nil, err
	}

	ControllerInfo := &secrets.ControllerInfo{
		PublicKey: []byte(certPEM),
	}

	tokenKeyPEMs := []*secrets.ControllerInfo{ControllerInfo}

	scrts, err := compactpki.NewCompactPKIWithTokenCA([]byte(keyPEM), []byte(certPEM), []byte(caPool), tokenKeyPEMs, txtToken, claimsheader.CompressionTypeV1)
	if err != nil {
		return nil, err
	}

	return scrts, nil
}

func createUncompressedTags(pu string) *policy.TagStore {
	tags := []string{
		enforcerconstants.TransmitterLabel + "=" + pu,
	}

	return policy.NewTagStoreFromSlice(tags)
}

func createCompressedTagArray() *policy.TagStore {
	return policy.NewTagStoreFromSlice([]string{
		"vpdCmPoRCx7k",
		"8wLk0bOXS9w0",
		"GUmf49pmErzC",
		"7J+9IX0dRGog",
		"3BQgvLnKvSUj",
	})
}

func Test_NewBinaryJWT(t *testing.T) {
	Convey("When I try to instantiate a new binary JWT, it should succeed", t, func() {
		b, err := NewBinaryJWT(bvalidity, "0123456789012345678901234567890123456789")
		So(err, ShouldBeNil)
		So(b, ShouldNotBeNil)
		So(b.ValidityPeriod, ShouldEqual, bvalidity)
		So(b.Issuer, ShouldEqual, "0123456789012345678901234567890123456789")
		So(b.tokenCache, ShouldNotBeNil)
		So(b.sharedKeys, ShouldNotBeNil)
	})
}

func Test_EncodeDecode(t *testing.T) {
	Convey("Given a validy binary JWT issuer", t, func() {
		scrts, err := createCompactPKISecrets([]string{"kDMRXWckV9k6mGuJ", "xyz", "eJ1s03u72o6i"})
		So(err, ShouldBeNil)

		b, err := NewBinaryJWT(bvalidity, "0123456789012345678901234567890123456789")
		So(err, ShouldBeNil)

		Convey("When I encode and decode a bad Syn Packet", func() {

			token := make([]byte, 400)
			token = append(token, []byte("abcdefghijklmnopqrstuvwxyz")...)

			Convey("When I decode the token, it should throw error", func() {
				_, _, _, _, _, err := b.DecodeSyn(false, token, nil, scrts, nil)
				So(err, ShouldResemble, ErrMissingSignature)
			})
		})

		Convey("When I encode and decode a nil Syn Packet", func() {

			Convey("When I decode the token, it should be give the original claims", func() {
				_, _, _, _, _, err := b.DecodeSyn(false, nil, nil, scrts, nil)
				So(err, ShouldResemble, ErrInvalidTokenLength)
			})
		})
	})
}

type TestPublicKey struct {
	X *big.Int
	Y *big.Int
}

func testencodeKey() ([]byte, error) {
	var data bytes.Buffer
	remotePrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return []byte{}, err
	}
	p := &TestPublicKey{
		X: remotePrivateKey.PublicKey.X,
		Y: remotePrivateKey.PublicKey.Y,
	}
	enc := gob.NewEncoder(&data)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return data.Bytes(), nil

}

type PublicKeys struct {
	X *big.Int
	Y *big.Int
}

func Test_BinaryTokenLengths(t *testing.T) {
	Convey("Given a JWT valid engine with a valid Compact PKI key ", t, func() {
		scrts, err := createCompactPKISecrets(nil)
		So(err, ShouldBeNil)

		t, err := NewBinaryJWT(bvalidity, "01234567890123456789012345678901234567")
		So(err, ShouldBeNil)

		Convey("When I try with 64 12-byte tags, the max length must not be exceeded", func() {

			privatekey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			So(err, ShouldBeNil)

			publickey := &PublicKeys{
				X: privatekey.PublicKey.X,
				Y: privatekey.PublicKey.Y,
			}

			var data bytes.Buffer

			enc := gob.NewEncoder(&data)
			err = enc.Encode(publickey)
			So(err, ShouldBeNil)
			msg := "Length of bytes " + strconv.Itoa(len(data.Bytes()))
			Convey(msg, func() {})

			var compressedTags []string
			b := make([]byte, 12)
			for i := 0; i < 56; i++ {
				_, err := rand.Read(b)
				So(err, ShouldBeNil)
				compressedTags = append(compressedTags, string(b))
			}

			claims := &ConnectionClaims{
				ID:  "5c5baa93d5f54a3019bede4e",
				RMT: []byte(rmt),
				LCL: []byte(lcl),
				CT:  policy.NewTagStoreFromSlice(compressedTags),
			}

			var encodedBuf [ClaimsEncodedBufSize]byte

			token, err := t.CreateSynToken(claims, encodedBuf[:], []byte(lcl), claimsheader.NewClaimsHeader(), scrts)
			So(err, ShouldBeNil)
			So(len(token), ShouldBeLessThan, 1420)
		})

	})

	Convey("Given a JWT valid engine with a valid Compact PKI key ", t, func() {
		scrts, err := createCompactPKISecrets(nil)
		So(err, ShouldBeNil)

		t, err := NewBinaryJWT(bvalidity, "0123456789012345678901234567890123456789")
		So(err, ShouldBeNil)

		Convey("When I try with 64 12-byte tags, the max length must not be exceeded", func() {

			privatekey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			So(err, ShouldBeNil)

			publickey := &PublicKeys{
				X: privatekey.PublicKey.X,
				Y: privatekey.PublicKey.Y,
			}

			var data bytes.Buffer

			enc := gob.NewEncoder(&data)
			err = enc.Encode(publickey)
			So(err, ShouldBeNil)
			msg := "Length of bytes " + strconv.Itoa(len(data.Bytes()))
			Convey(msg, func() {})

			var compressedTags []string
			b := make([]byte, 8)
			for i := 0; i < 80; i++ {
				_, err := rand.Read(b)
				So(err, ShouldBeNil)
				compressedTags = append(compressedTags, string(b))
			}

			claims := &ConnectionClaims{
				ID:  "5c5baa93d5f54a3019bede4e",
				RMT: []byte(rmt),
				LCL: []byte(lcl),
				CT:  policy.NewTagStoreFromSlice(compressedTags),
			}
			var encodedBuf [ClaimsEncodedBufSize]byte
			token, err := t.CreateSynToken(claims, encodedBuf[:], []byte(lcl), claimsheader.NewClaimsHeader(), scrts)
			So(err, ShouldBeNil)
			So(len(token), ShouldBeLessThan, 1420)
		})

	})
}

func Test_PANWIdentitySynToken(t *testing.T) {
	Convey("Given a JWT valid engine with a valid Compact PKI key ", t, func() {
		scrts, err := createCompactPKISecrets(nil)
		So(err, ShouldBeNil)

		t1, err := NewBinaryJWT(bvalidity, "01234567890123456789012345678901234567")
		So(err, ShouldBeNil)

		Convey("PANWIDENTITY string should be there at 64 byte boundary from the end of the token", func() {

			privatekey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			So(err, ShouldBeNil)

			publickey := &PublicKeys{
				X: privatekey.PublicKey.X,
				Y: privatekey.PublicKey.Y,
			}

			var data bytes.Buffer

			enc := gob.NewEncoder(&data)
			err = enc.Encode(publickey)
			So(err, ShouldBeNil)
			msg := "Length of bytes " + strconv.Itoa(len(data.Bytes()))
			Convey(msg, func() {})

			var compressedTags []string
			b := make([]byte, 12)
			for i := 0; i < 56; i++ {
				_, err := rand.Read(b)
				So(err, ShouldBeNil)
				compressedTags = append(compressedTags, string(b))
			}

			claims := &ConnectionClaims{
				ID:  "5c5baa93d5f54a3019bede4e",
				RMT: []byte(rmt),
				LCL: []byte(lcl),
				CT:  policy.NewTagStoreFromSlice(compressedTags),
			}

			var encodedBuf [ClaimsEncodedBufSize]byte

			synToken, err := t1.CreateSynToken(claims, encodedBuf[:], []byte(lcl), claimsheader.NewClaimsHeader(), scrts)
			So(err, ShouldBeNil)
			startOffset := len(synToken) - 64 - len([]byte("PANWIDENTITY"))
			endOffset := len(synToken) - 64
			assert.Equal(t, string(synToken[startOffset:endOffset]), "PANWIDENTITY", "string should match PANWIDENTITY")
		})

	})
}

func Test_PANWIdentityAckToken(t *testing.T) {

	Convey("Given a JWT valid engine with a valid Compact PKI key ", t, func() {
		t1, err := NewBinaryJWT(bvalidity, "0123456789012345678901234567890123456789")
		So(err, ShouldBeNil)

		var compressedTags []string
		b := make([]byte, 12)
		for i := 0; i < 56; i++ {
			_, err := rand.Read(b)
			So(err, ShouldBeNil)
			compressedTags = append(compressedTags, string(b))
		}

		claims := &ConnectionClaims{
			ID:  "5c5baa93d5f54a3019bede4e",
			RMT: []byte(rmt),
			LCL: []byte(lcl),
			CT:  policy.NewTagStoreFromSlice(compressedTags),
		}

		var encodedBuf [ClaimsEncodedBufSize]byte

		ackToken, err := t1.CreateAckToken(false, []byte("hello"), claims, encodedBuf[:], claimsheader.NewClaimsHeader())
		So(err, ShouldBeNil)
		startOffset := len(ackToken) - 64 - len([]byte("PANWIDENTITY"))
		endOffset := len(ackToken) - 64
		assert.Equal(t, string(ackToken[startOffset:endOffset]), "PANWIDENTITY", "string should match PANWIDENTITY")
	})
}

func Test_EncDecClaims(t *testing.T) {
	var compressedTags []string
	b := make([]byte, 12)
	for i := 0; i < 56; i++ {
		rand.Read(b) //nolint
		compressedTags = append(compressedTags, string(b))
	}

	// Encode the claims in a buffer.

	claims := &ConnectionClaims{
		ID:  "5c5baa93d5f54a3019bede4e",
		RMT: []byte(rmt),
		LCL: []byte(lcl),
		CT:  policy.NewTagStoreFromSlice(compressedTags),
	}
	allclaims := ConvertToBinaryClaims(claims, 1*time.Minute)

	var encodedBuf [ClaimsEncodedBufSize]byte
	encBuf := encodedBuf[:]
	encode(allclaims, &encBuf) //nolint

	decClaims, _ := decode(encBuf)
	eq := reflect.DeepEqual(allclaims, decClaims)

	assert.Equal(t, eq, true, "decoded claims should be equal to original claims which was encoded")
}
