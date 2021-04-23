// +build !windows

package claimsheader

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestHeaderBytes(t *testing.T) {

	Convey("Given I create a new header bytes", t, func() {
		header := NewClaimsHeader(
			OptionCompressionType(CompressionTypeV1),
			OptionEncrypt(true),
			OptionDatapathVersion(DatapathVersion1),
			OptionPing(true),
		).ToBytes()

		Convey("Then header bytes should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I convert bytes to claims header", func() {
			ch := header.ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.compressionType, ShouldEqual, CompressionTypeV1)
				So(ch.encrypt, ShouldEqual, true)
				So(ch.datapathVersion, ShouldEqual, DatapathVersion1)
				So(ch.ping, ShouldEqual, true)
			})
		})
	})
}
