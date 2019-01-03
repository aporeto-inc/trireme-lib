package nfqdatapath

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
)

func testClaimsHeader(encrypt uint8) ClaimsHeader {

	return ClaimsHeader{
		CompressionType: constants.CompressionTypeV2Mask,
		Encrypt:         encrypt,
		HandshakeType:   HandshakeVersion,
	}
}

func TestHeader(t *testing.T) {

	Convey("Given I generate a claims header with encrypt set", t, func() {
		header := GenerateClaimsHeader(testClaimsHeader(encryptionAttr(true)))

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I compare the claims header if the right bit set", func() {
			equal := CompareClaimsHeaderAttribute(header, constants.CompressionTypeV2Mask, constants.CompressionTypeMask)

			Convey("Then it should be equal", func() {
				So(equal, ShouldBeTrue)
			})
		})

		Convey("Given I compare the claims header with wrong type", func() {
			equal := CompareClaimsHeaderAttribute(header, constants.CompressionTypeV1Mask, constants.CompressionTypeMask)

			Convey("Then it should not be equal", func() {
				So(equal, ShouldBeFalse)
			})
		})

		Convey("Given I compare the claims header with right bit set and different attribute", func() {
			equal := CompareClaimsHeaderAttribute(header, encryptionAttr(true), tokens.EncryptionEnabledMask)

			Convey("Then it should be equal", func() {
				So(equal, ShouldBeTrue)
			})
		})

		Convey("Given I compare the claims header with right bit set and different attribute with wrong bit", func() {
			equal := CompareClaimsHeaderAttribute(header, encryptionAttr(false), tokens.EncryptionEnabledMask)

			Convey("Then it should not be equal", func() {
				So(equal, ShouldBeFalse)
			})
		})

		Convey("Given I compare the claims header of handhskae", func() {
			equal := CompareClaimsHeaderAttribute(header, HandshakeVersion, HandshakeVersion)

			Convey("Then it should be equal", func() {
				So(equal, ShouldBeTrue)
			})
		})
	})

	Convey("Given I generate a claims header with encrypt not set", t, func() {
		header := GenerateClaimsHeader(testClaimsHeader(encryptionAttr(false)))

		Convey("Then claims header should not be nil", func() {
			So(header, ShouldNotBeNil)
		})

		Convey("Given I compare the claims header with right bit set", func() {
			equal := CompareClaimsHeaderAttribute(header, constants.CompressionTypeV2Mask, constants.CompressionTypeMask)

			Convey("Then it should be equal", func() {
				So(equal, ShouldBeTrue)
			})
		})

		Convey("Given I compare the claims header with wrong bit set", func() {
			equal := CompareClaimsHeaderAttribute(header, constants.CompressionTypeV1Mask, constants.CompressionTypeMask)

			Convey("Then it should not be equal", func() {
				So(equal, ShouldBeFalse)
			})
		})

		Convey("Given I compare the claims header with right bit set and different attribute", func() {
			equal := CompareClaimsHeaderAttribute(header, encryptionAttr(true), tokens.EncryptionEnabledMask)

			Convey("Then it should not be equal", func() {
				So(equal, ShouldBeFalse)
			})
		})

		Convey("Given I compare the claims header with right bit set and different attribute with wrong bit", func() {
			equal := CompareClaimsHeaderAttribute(header, encryptionAttr(false), tokens.EncryptionEnabledMask)

			Convey("Then it should be equal", func() {
				So(equal, ShouldBeTrue)
			})
		})
	})
}
