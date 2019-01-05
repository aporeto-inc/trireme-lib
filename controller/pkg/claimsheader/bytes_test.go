package claimsheader

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

)

func TestHeaderBytes(t *testing.T) {

	Convey("Given I create a new header bytes", t, func() {
		header := NewClaimsHeader(
			OptionCompressionType(compressionTypeV2Mask),
			OptionEncrypt(true),
			OptionHandshakeVersion(HandshakeVersion),
		).ToBytes()

		Convey("Then header bytes should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I convert bytes to claims header", func() {
			ch := header.ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.compressionType, ShouldEqual, compressionTypeV2Mask)
				So(ch.encrypt, ShouldEqual, true)
				So(ch.handshakeVersion, ShouldEqual, HandshakeVersion)
			})
		})
	})
}
