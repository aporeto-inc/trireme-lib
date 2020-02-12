package tokens

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/policy"
)

var (
	pu1nonce  = []byte("0123456789012345")
	pu2nonce  = []byte("0987654321098765")
	pu1Claims = ConnectionClaims{
		ID:  "pu1",
		T:   createUncompressedTags("pu1"),
		CT:  createCompressedTagArray(),
		LCL: pu1nonce,
	}

	pu2Claims = ConnectionClaims{
		ID:       "pu2",
		T:        createUncompressedTags("pu2"),
		CT:       createCompressedTagArray(),
		LCL:      pu2nonce,
		RMT:      pu1nonce,
		RemoteID: "pu1",
	}

	pu1AckClaims = ConnectionClaims{
		ID:       "pu1",
		RMT:      pu2nonce,
		LCL:      pu1nonce,
		EK:       []byte{},
		RemoteID: "pu2",
	}
	bvalidity = time.Second * 10

	header = claimsheader.NewClaimsHeader(
		claimsheader.OptionCompressionType(claimsheader.CompressionTypeV1),
	)
)

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
		cert, scrts, err := createCompactPKISecrets()
		So(err, ShouldBeNil)

		b, err := NewBinaryJWT(bvalidity, "0123456789012345678901234567890123456789")
		So(err, ShouldBeNil)

		Convey("When I encode and decode a Syn Packet", func() {
			token, err := b.CreateAndSign(false, &pu1Claims, pu1nonce, header, scrts)

			Convey("I should succeed", func() {
				So(err, ShouldBeNil)
				So(len(token), ShouldBeGreaterThan, 0)
			})

			Convey("When I decode the token, it should be give the original claims", func() {
				outClaims, outNonce, outKey, err := b.Decode(false, token, nil, scrts)
				So(err, ShouldBeNil)
				So(outKey, ShouldResemble, cert.PublicKey)
				So(outNonce, ShouldResemble, pu1nonce)
				So(outClaims, ShouldNotBeNil)
				So(outClaims.LCL, ShouldResemble, pu1Claims.LCL)
				So(outClaims.RMT, ShouldResemble, pu1Claims.RMT)
				So(outClaims.ID, ShouldEqual, pu1Claims.ID)
				So(len(outClaims.T.Tags), ShouldEqual, 6)
				So(outClaims.T.Tags, ShouldContain, "AporetoContextID=pu1")
			})

		})

		Convey("When I encode and decode a bad Syn Packet", func() {

			token := make([]byte, 400)
			token = append(token, []byte("abcdefghijklmnopqrstuvwxyz")...)

			Convey("When I decode the token, it should be give the original claims", func() {
				_, _, _, err := b.Decode(false, token, nil, nil)
				So(err, ShouldResemble, fmt.Errorf("unable to unpack token: no signature in the token"))
			})
		})

		Convey("When I encode and decode a nil Syn Packet", func() {

			Convey("When I decode the token, it should be give the original claims", func() {
				_, _, _, err := b.Decode(false, nil, nil, nil)
				So(err, ShouldResemble, fmt.Errorf("unable to unpack token: not enough data"))
			})
		})
	})
}

func Test_Syn_SynAck_Sequence(t *testing.T) {
	Convey("Given a validy binary JWT issuer", t, func() {
		cert, scrts, err := createCompactPKISecrets()
		So(err, ShouldBeNil)

		b, err := NewBinaryJWT(bvalidity, "0123456789012345678901234567890123456789")
		So(err, ShouldBeNil)

		Convey("When I encode and send a Syn Token", func() {
			token, err := b.CreateAndSign(false, &pu1Claims, pu1nonce, header, scrts)
			Convey("I should succeed", func() {
				So(err, ShouldBeNil)
				So(len(token), ShouldBeGreaterThan, 0)
			})

			outClaims, outNonce, outKey, err := b.Decode(false, token, nil, scrts)
			Convey("Decoding of the Syn should be done", func() {
				So(err, ShouldBeNil)
				So(outKey, ShouldResemble, cert.PublicKey)
				So(outNonce, ShouldResemble, pu1nonce)
				So(outClaims, ShouldNotBeNil)
				So(outClaims.LCL, ShouldResemble, pu1Claims.LCL)
				So(outClaims.RMT, ShouldResemble, pu1Claims.RMT)
				So(outClaims.ID, ShouldEqual, pu1Claims.ID)
				So(len(outClaims.T.Tags), ShouldEqual, 6)
				So(outClaims.T.Tags, ShouldContain, "AporetoContextID=pu1")
			})

			Convey("When I send the SynAck token after that, it should also be decoded with a shared key", func() {

				saToken, err := b.CreateAndSign(false, &pu2Claims, pu2nonce, header, scrts)
				So(err, ShouldBeNil)

				saClaims, _, _, err := b.Decode(false, saToken, nil, scrts)
				So(err, ShouldBeNil)
				So(saClaims, ShouldNotBeNil)
				So(saClaims.LCL, ShouldResemble, pu2Claims.LCL)
				So(saClaims.RMT, ShouldBeNil)
				So(saClaims.ID, ShouldResemble, pu2Claims.ID)

				Convey("When I send the final Ack packet it should also be decoded with the shared key", func() {

					ackToken, err := b.CreateAndSign(true, &pu1AckClaims, nil, header, scrts)
					So(err, ShouldBeNil)
					So(ackToken, ShouldNotBeNil)

					sackClaims, _, _, err := b.Decode(true, ackToken, nil, scrts)
					So(err, ShouldBeNil)
					So(sackClaims, ShouldNotBeNil)
				})
			})

		})
	})
}

type PublicKeys struct {
	X *big.Int
	Y *big.Int
}

func Test_BinaryTokenLengths(t *testing.T) {
	Convey("Given a JWT valid engine with a valid Compact PKI key ", t, func() {
		_, scrts, err := createCompactPKISecrets()
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
				EK:  data.Bytes(),
				CT:  policy.NewTagStoreFromSlice(compressedTags),
			}

			token, err := t.CreateAndSign(false, claims, pu1nonce, claimsheader.NewClaimsHeader(), scrts)
			So(err, ShouldBeNil)
			So(len(token), ShouldBeLessThan, 1420)
		})

	})

	Convey("Given a JWT valid engine with a valid Compact PKI key ", t, func() {
		_, scrts, err := createCompactPKISecrets()
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
				EK:  data.Bytes(),
				CT:  policy.NewTagStoreFromSlice(compressedTags),
			}

			token, err := t.CreateAndSign(false, claims, pu1nonce, claimsheader.NewClaimsHeader(), scrts)
			So(err, ShouldBeNil)
			So(len(token), ShouldBeLessThan, 1420)
		})

	})
}
