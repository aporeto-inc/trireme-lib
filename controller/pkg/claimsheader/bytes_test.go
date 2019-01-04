package claimsheader

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestHeaderBytes(t *testing.T) {

	Convey("Given I create a new bytes", t, func() {
		header := NewClaimsHeader(
			OptionCompressionType(CompressionTypeV2Mask),
			OptionEncrypt(true),
			OptionHandshakeVersion(HandshakeVersion),
		).ToBytes()

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I compare the claims header if the right bit set", func() {
			ch := header.ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.compressionType, ShouldEqual, CompressionTypeV2Mask)
				So(ch.encrypt, ShouldEqual, true)
				So(ch.handshakeVersion, ShouldEqual, HandshakeVersion)
			})
		})
	})
}
