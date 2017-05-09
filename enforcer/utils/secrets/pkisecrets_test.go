package secrets

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"github.com/aporeto-inc/trireme/crypto"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewPKISecrets(t *testing.T) {

	Convey("When I create a new  PKI secret , it should succeed ", t, func() {

		p, err := NewPKISecrets([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM), nil)
		So(err, ShouldBeNil)
		So(p, ShouldNotBeNil)
		So(p.AuthorityPEM, ShouldResemble, []byte(caPEM))
		So(p.PrivateKeyPEM, ShouldResemble, []byte(privateKeyPEM))
		So(p.PublicKeyPEM, ShouldResemble, []byte(publicPEM))
	})

	Convey("When I create a new compact PKI with invalid certs, it should fail", t, func() {
		p, err := NewPKISecrets([]byte(privateKeyPEM)[:20], []byte(publicPEM)[:30], []byte(caPEM), nil)
		So(err, ShouldNotBeNil)
		So(p, ShouldBeNil)
	})

	Convey("When I create a new compact PKI with invalid CA, it should fail", t, func() {
		p, err := NewPKISecrets([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM)[:10], nil)
		So(err, ShouldNotBeNil)
		So(p, ShouldBeNil)
	})

}

func TestPKIBasicInterfaceFunctions(t *testing.T) {

	Convey("Given a valid CompactPKI ", t, func() {
		p, err := NewPKISecrets([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM), nil)
		So(err, ShouldBeNil)
		So(p, ShouldNotBeNil)

		key, cert, _, _ := crypto.LoadAndVerifyECSecrets([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM))
		Convey("I should get the right secrets type ", func() {
			So(p.Type(), ShouldResemble, PKIType)
		})

		Convey("I should get the right encoding key", func() {
			So(*(p.EncodingKey().(*ecdsa.PrivateKey)), ShouldResemble, *key)
		})

		Convey("I should get the right transmitter key", func() {
			So(p.TransmittedKey(), ShouldResemble, []byte(publicPEM))
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

		Convey("I should ge the righ ack size", func() {
			So(p.AckSize(), ShouldEqual, 336)
		})

		Convey("I should get the right public key, ", func() {
			So(p.PublicKey().(*x509.Certificate), ShouldResemble, cert)
		})

		Convey("When I verify the received public key, it should succeed", func() {
			pk, err := p.VerifyPublicKey([]byte(publicPEM))
			So(err, ShouldBeNil)
			So(pk, ShouldResemble, cert)
		})

		Convey("When I verify and there is a bad key, I should get an error", func() {
			_, err := p.VerifyPublicKey([]byte(publicPEM[:10]))
			So(err, ShouldNotBeNil)
		})

		Convey("When I try to get the decoding key when the ack key is nil", func() {
			key, err := p.DecodingKey("server", cert, nil)
			So(err, ShouldBeNil)
			So(key, ShouldResemble, cert.PublicKey.(*ecdsa.PublicKey))
		})

		Convey("When I try to get the decoding key with the ack", func() {
			key, err := p.DecodingKey("server", nil, cert.PublicKey.(*ecdsa.PublicKey))
			So(err, ShouldBeNil)
			So(key, ShouldResemble, cert.PublicKey.(*ecdsa.PublicKey))
		})

		Convey("When I try to get the decoding key and both inputs are nil, I should get an error ", func() {
			_, err := p.DecodingKey("server", nil, nil)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestPKICache(t *testing.T) {
	Convey("Given PKI secrets with a cache", t, func() {
		_, cert, _, _ := crypto.LoadAndVerifyECSecrets([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM))
		cache := map[string]*ecdsa.PublicKey{}
		p, err := NewPKISecrets([]byte(privateKeyPEM), []byte(publicPEM), []byte(caPEM), cache)
		So(err, ShouldBeNil)
		So(p, ShouldNotBeNil)
		So(p.CertificateCache, ShouldEqual, cache)

		Convey("When I add a certificate in the cache for server1", func() {
			err := p.PublicKeyAdd("server1", []byte(publicPEM))
			So(err, ShouldBeNil)
			Convey("If I try to get the decoding key for the server, it should succeed ", func() {
				key, err := p.DecodingKey("server1", nil, nil)
				So(err, ShouldBeNil)
				So(key, ShouldResemble, cert.PublicKey.(*ecdsa.PublicKey))
			})
			Convey("If I try to get the decoding key for another server that is not in the cache, it should fail ", func() {
				_, err := p.DecodingKey("server2", nil, nil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add a bad certificate in the cache for server1, I should get an error ", func() {
			err := p.PublicKeyAdd("server1", []byte(publicPEM[:10]))
			So(err, ShouldNotBeNil)
		})

	})
}
