package claimsheader

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestHeader(t *testing.T) {

	Convey("Given I create a new claims header", t, func() {
		header := NewClaimsHeader(
			OptionEncrypt(true),
			OptionCompressionType(CompressionTypeV2),
			OptionDatapathVersion(DatapathVersion1),
			OptionDiagnosticType(DiagnosticTypeNone),
		).ToBytes()

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I convert bytes to claims header", func() {
			ch := header.ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeV2)
				So(ch.Encrypt(), ShouldEqual, true)
				So(ch.DatapathVersion(), ShouldEqual, DatapathVersion1)
				So(ch.DiagnosticType(), ShouldEqual, DiagnosticTypeNone)
				So(ch.DiagnosticType().String(), ShouldEqual, "None")
			})
		})
	})

	Convey("Given I create a new claims header with pass through", t, func() {
		header := NewClaimsHeader(
			OptionEncrypt(false),
			OptionCompressionType(CompressionTypeV2),
			OptionDatapathVersion(DatapathVersion1),
			OptionDiagnosticType(DiagnosticTypeAporetoIdentity),
		)

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I convert bytes to claims header", func() {
			ch := header.ToBytes().ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeV2)
				So(ch.Encrypt(), ShouldEqual, false)
				So(ch.DatapathVersion(), ShouldEqual, DatapathVersion1)
				So(ch.DiagnosticType(), ShouldEqual, DiagnosticTypeAporetoIdentity)
				So(ch.DiagnosticType().String(), ShouldEqual, "AporetoIdentity")
			})
		})

		Convey("Given I set change headers", func() {
			header.SetCompressionType(CompressionTypeV2)
			header.SetEncrypt(true)
			header.SetDiagnosticType(DiagnosticTypeAporetoIdentityPassthrough)
			ch := header.ToBytes().ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeV2)
				So(ch.Encrypt(), ShouldEqual, true)
				So(ch.DatapathVersion(), ShouldEqual, DatapathVersion1)
				So(ch.DiagnosticType(), ShouldEqual, DiagnosticTypeAporetoIdentityPassthrough)
				So(ch.DiagnosticType().String(), ShouldEqual, "AporetoIdentityPassthrough")
			})
		})
	})

	Convey("Given I create a new claims header with custom token pass through", t, func() {
		header := NewClaimsHeader(
			OptionEncrypt(false),
			OptionCompressionType(CompressionTypeV2),
			OptionDatapathVersion(DatapathVersion1),
			OptionDiagnosticType(DiagnosticTypeCustomIdentity),
		)

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I convert bytes to claims header", func() {
			ch := header.ToBytes().ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeV2)
				So(ch.Encrypt(), ShouldEqual, false)
				So(ch.DatapathVersion(), ShouldEqual, DatapathVersion1)
				So(ch.DiagnosticType(), ShouldEqual, DiagnosticTypeCustomIdentity)
				So(ch.DiagnosticType().String(), ShouldEqual, "CustomIdentity")
			})
		})

		Convey("Given I set change headers", func() {
			header.SetCompressionType(CompressionTypeV2)
			header.SetEncrypt(true)
			header.SetDiagnosticType(DiagnosticTypeAporetoIdentityPassthrough)
			ch := header.ToBytes().ToClaimsHeader()
			fmt.Println(DiagnosticTypeAporetoIdentity)
			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeV2)
				So(ch.Encrypt(), ShouldEqual, true)
				So(ch.DatapathVersion(), ShouldEqual, DatapathVersion1)
				So(ch.DiagnosticType(), ShouldEqual, DiagnosticTypeAporetoIdentityPassthrough)
				So(ch.DiagnosticType().String(), ShouldEqual, "AporetoIdentityPassthrough")
			})
		})
	})

	Convey("Given I create a new claims header and encrypt false", t, func() {
		header := NewClaimsHeader(
			OptionEncrypt(false),
			OptionCompressionType(CompressionTypeV1),
			OptionDatapathVersion(DatapathVersion1),
		).ToBytes()

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I convert bytes to claims header", func() {
			ch := header.ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeV1)
				So(ch.Encrypt(), ShouldEqual, false)
				So(ch.DatapathVersion(), ShouldEqual, DatapathVersion1)
			})
		})
	})

	Convey("Given I create a new claims header and with no encryption type", t, func() {
		header := NewClaimsHeader(
			OptionEncrypt(false),
			OptionDatapathVersion(DatapathVersion1),
		).ToBytes()

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I convert bytes to claims header", func() {
			ch := header.ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeNone)
				So(ch.Encrypt(), ShouldEqual, false)
				So(ch.DatapathVersion(), ShouldEqual, DatapathVersion1)
			})
		})
	})

	Convey("Given I create a new claims header and change it later", t, func() {
		header := NewClaimsHeader(
			OptionEncrypt(false),
			OptionDatapathVersion(DatapathVersion1),
			OptionDiagnosticType(DiagnosticTypeAporetoIdentity),
		)

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I convert bytes to claims header", func() {
			ch := header.ToBytes().ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeNone)
				So(ch.Encrypt(), ShouldEqual, false)
				So(ch.DatapathVersion(), ShouldEqual, DatapathVersion1)
				So(ch.DiagnosticType(), ShouldEqual, DiagnosticTypeAporetoIdentity)
			})
		})

		Convey("Given I set different compression type and encrypt", func() {
			header.SetCompressionType(CompressionTypeV2)
			header.SetEncrypt(true)
			header.SetDiagnosticType(DiagnosticTypeNone)
			ch := header.ToBytes().ToClaimsHeader()

			Convey("Then it should be equal", func() {
				So(ch.CompressionType(), ShouldEqual, CompressionTypeV2)
				So(ch.Encrypt(), ShouldEqual, true)
				So(ch.DatapathVersion(), ShouldEqual, DatapathVersion1)
				So(ch.DiagnosticType(), ShouldEqual, DiagnosticTypeNone)
			})
		})
	})

	Convey("Given I try retrieve fields without any data", t, func() {
		ch := &ClaimsHeader{}

		Convey("Then it should be equal", func() {
			So(ch.CompressionType(), ShouldEqual, CompressionTypeNone)
			So(ch.Encrypt(), ShouldEqual, false)
			So(ch.DatapathVersion(), ShouldEqual, DatapathVersion1)
		})
	})
}
