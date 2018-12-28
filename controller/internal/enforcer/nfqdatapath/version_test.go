package nfqdatapath

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
)

func testVersion(encrypt uint8) Version {

	return Version{
		CompressionType: constants.CompressionTypeV2Mask,
		Encrypt:         encrypt,
		HandshakeType:   HandshakeVersion,
	}
}

func TestVersion(t *testing.T) {

	Convey("Given I generate a version with encrypt set", t, func() {
		version := GenerateVersion(testVersion(encryptionAttr(true)))

		Convey("Then version should not be nil", func() {
			So(version, ShouldNotBeNil)
		})

		Convey("Given I compare the version if the right bit set", func() {
			equal := CompareVersionAttribute([]byte(version), constants.CompressionTypeV2Mask, constants.CompressionTypeMask)

			Convey("Then it should be equal", func() {
				So(equal, ShouldBeTrue)
			})
		})

		Convey("Given I compare the version with wrong type", func() {
			equal := CompareVersionAttribute([]byte(version), constants.CompressionTypeV1Mask, constants.CompressionTypeMask)

			Convey("Then it should not be equal", func() {
				So(equal, ShouldBeFalse)
			})
		})

		Convey("Given I compare the version with right bit set and different attribute", func() {
			equal := CompareVersionAttribute([]byte(version), encryptionAttr(true), tokens.EncryptionEnabledMask)

			Convey("Then it should be equal", func() {
				So(equal, ShouldBeTrue)
			})
		})

		Convey("Given I compare the version with right bit set and different attribute with wrong bit", func() {
			equal := CompareVersionAttribute([]byte(version), encryptionAttr(false), tokens.EncryptionEnabledMask)

			Convey("Then it should not be equal", func() {
				So(equal, ShouldBeFalse)
			})
		})

		Convey("Given I compare the version of handhskae", func() {
			equal := CompareVersionAttribute([]byte(version), HandshakeVersion, HandshakeVersion)

			Convey("Then it should be equal", func() {
				So(equal, ShouldBeTrue)
			})
		})
	})

	Convey("Given I generate a version with encrypt not set", t, func() {
		version := GenerateVersion(testVersion(encryptionAttr(false)))

		Convey("Then version should not be nil", func() {
			So(version, ShouldNotBeNil)
		})

		Convey("Given I compare the version with right bit set", func() {
			equal := CompareVersionAttribute([]byte(version), constants.CompressionTypeV2Mask, constants.CompressionTypeMask)

			Convey("Then it should be equal", func() {
				So(equal, ShouldBeTrue)
			})
		})

		Convey("Given I compare the version with wrong bit set", func() {
			equal := CompareVersionAttribute([]byte(version), constants.CompressionTypeV1Mask, constants.CompressionTypeMask)

			Convey("Then it should not be equal", func() {
				So(equal, ShouldBeFalse)
			})
		})

		Convey("Given I compare the version with right bit set and different attribute", func() {
			equal := CompareVersionAttribute([]byte(version), encryptionAttr(true), tokens.EncryptionEnabledMask)

			Convey("Then it should not be equal", func() {
				So(equal, ShouldBeFalse)
			})
		})

		Convey("Given I compare the version with right bit set and different attribute with wrong bit", func() {
			equal := CompareVersionAttribute([]byte(version), encryptionAttr(false), tokens.EncryptionEnabledMask)

			Convey("Then it should be equal", func() {
				So(equal, ShouldBeTrue)
			})
		})
	})
}
