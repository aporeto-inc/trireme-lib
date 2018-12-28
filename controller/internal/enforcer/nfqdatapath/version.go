package nfqdatapath

import (
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
	"go.uber.org/zap"
)

// HandshakeVersion is the enforcer version
// TODO: Enable this in datapath
const HandshakeVersion = 0x40

// Version holds version sub attributes
type Version struct {
	// CompressionType represents compressed tag mode attribute
	CompressionType uint8
	// Encrypt represents enryption enabled attribute
	Encrypt uint8
	// Handshake type represents handshake version
	HandshakeType uint8
}

// GenerateVersion generates the 32-bit version field
// version holds all the version sub attributes
func GenerateVersion(version Version) []byte {

	// This is a 32 bit version used to be a symmetric identification between enforcers
	// Byte 0 : Bits 0,1 represents compressed tag mode.
	//          Bit 2 represents enryption enabled.
	//          Bits [3:6] represents handshake version.
	//          Bits [7] reserved for future use. (currently unused).
	// Bytes [1:3]: reserved for future use.

	versionData := make([]byte, tokens.MaxVersionLen)
	versionData[0] |= version.CompressionType
	versionData[0] |= version.Encrypt
	versionData[0] |= version.HandshakeType

	return versionData
}

// CompareVersionAttribute compares the given version attribute
// with the given 32-bit version field.
// version is the complete 32-bit version field
// versionAttr is the version sub attribute
// mask is the bit comparison
func CompareVersionAttribute(version []byte, versionAttr uint8, mask uint8) bool {

	// check if the set version attribute is NOT the given version attribute and return false
	if parseVersionAttr(version, mask) != versionAttr {
		zap.L().Debug("Version doesn't match",
			zap.String("version", string(version)),
			zap.String("versionAttribute", string(versionAttr)))

		return false
	}

	return true
}

// parseVersionAttr returns the version attribute set
func parseVersionAttr(version []byte, mask uint8) byte {

	return version[0] & mask
}

func encryptionAttr(encrypt bool) uint8 {

	if !encrypt {
		return 0x0
	}

	return tokens.EncryptionEnabledMask
}
