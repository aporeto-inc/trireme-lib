package claimsheader

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestHeader(t *testing.T) {

	Convey("Given I create a new claims header", t, func() {
		header := NewClaimsHeader(
			OptionEncrypt(true),
			OptionCompressionType(CompressionTypeV2Mask),
			OptionHandshakeVersion(HandshakeVersion),
		).ToBytes()

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I compare the claims header if the right bit set", func() {
			ch := header.ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeV2)
				So(ch.Encrypt(), ShouldEqual, true)
			})
		})
	})

	Convey("Given I create a new claims header and encrypt false", t, func() {
		header := NewClaimsHeader(
			OptionEncrypt(false),
			OptionCompressionType(CompressionTypeV1Mask),
			OptionHandshakeVersion(HandshakeVersion),
		).ToBytes()

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I compare the claims header if the right bit set", func() {
			ch := header.ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeV1)
				So(ch.Encrypt(), ShouldEqual, false)
			})
		})
	})

	Convey("Given I try to get compression type without data", t, func() {

		Convey("Given I compare the claims header if the right bit set", func() {
			ch := &ClaimsHeader{}

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeNone)
				So(ch.Encrypt(), ShouldEqual, false)
			})
		})
	})
}
