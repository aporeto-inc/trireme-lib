package claimsheader

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/constants"
)

func TestHeader(t *testing.T) {

	Convey("Given I create a new claims header", t, func() {
		header := NewClaimsHeader(
			OptionEncrypt(true),
			OptionCompressionType(constants.CompressionTypeV2Mask),
			OptionHandshakeVersion(HandshakeVersion),
		).ToBytes()

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I compare the claims header if the right bit set", func() {
			ch := header.ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, constants.CompressionTypeV2)
				So(ch.Encrypt(), ShouldEqual, true)
			})
		})
	})

	Convey("Given I create a new claims header and encrypt false", t, func() {
		header := NewClaimsHeader(
			OptionEncrypt(false),
			OptionCompressionType(constants.CompressionTypeV1Mask),
			OptionHandshakeVersion(HandshakeVersion),
		).ToBytes()

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I compare the claims header if the right bit set", func() {
			ch := header.ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, constants.CompressionTypeV1)
				So(ch.Encrypt(), ShouldEqual, false)
			})
		})
	})

	Convey("Given I try to get compression type without data", t, func() {

		Convey("Given I compare the claims header if the right bit set", func() {
			ch := &ClaimsHeader{}

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, constants.CompressionTypeNone)
				So(ch.Encrypt(), ShouldEqual, false)
			})
		})
	})
}
