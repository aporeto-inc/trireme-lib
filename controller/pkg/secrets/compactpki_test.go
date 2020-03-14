// +build !windows

package secrets

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/utils/crypto"
)

func TestNewCompactPKI(t *testing.T) {
	txKey := CreateTxtToken()
	// txkey is a token that has the client public key signed by the CA
	Convey("When I create a new compact PKI, it should succeed ", t, func() {

		p, err := NewCompactPKI([]byte(PrivateKeyPEM), []byte(PublicPEM), []byte(CAPEM), txKey, claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		So(p, ShouldNotBeNil)
		So(p.AuthorityPEM, ShouldResemble, []byte(CAPEM))
		So(p.PrivateKeyPEM, ShouldResemble, []byte(PrivateKeyPEM))
		So(p.PublicKeyPEM, ShouldResemble, []byte(PublicPEM))
	})

	Convey("When I create a new compact PKI with invalid certs, it should fail", t, func() {
		p, err := NewCompactPKI([]byte(PrivateKeyPEM)[:20], []byte(PublicPEM)[:30], []byte(CAPEM), txKey, claimsheader.CompressionTypeNone)
		So(err, ShouldNotBeNil)
		So(p, ShouldBeNil)
	})

	Convey("When I create a new compact PKI with invalid CA, it should fail", t, func() {
		p, err := NewCompactPKI([]byte(PrivateKeyPEM), []byte(PublicPEM), []byte(CAPEM)[:10], txKey, claimsheader.CompressionTypeNone)
		So(err, ShouldNotBeNil)
		So(p, ShouldBeNil)
	})

}

func TestBasicInterfaceFunctions(t *testing.T) {
	txKey := CreateTxtToken()
	Convey("Given a valid CompactPKI ", t, func() {
		p, err := NewCompactPKI([]byte(PrivateKeyPEM), []byte(PublicPEM), []byte(CAPEM), txKey, claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		So(p, ShouldNotBeNil)

		key, cert, _, _ := crypto.LoadAndVerifyECSecrets([]byte(PrivateKeyPEM), []byte(PublicPEM), []byte(CAPEM))
		Convey("I should get the right secrets type ", func() {
			So(p.Type(), ShouldResemble, PKICompactType)
		})

		Convey("I should get the right encoding key", func() {
			So(*(p.EncodingKey().(*ecdsa.PrivateKey)), ShouldResemble, *key)
		})

		Convey("I should get the right transmitter key", func() {
			So(p.TransmittedKey(), ShouldResemble, txKey)
		})

		Convey("I should ge the right ack size", func() {
			So(p.AckSize(), ShouldEqual, compactPKIAckSize)
		})

		Convey("I should get the right public key, ", func() {
			So(p.PublicKey().(*x509.Certificate), ShouldResemble, cert)
		})
	})
}
