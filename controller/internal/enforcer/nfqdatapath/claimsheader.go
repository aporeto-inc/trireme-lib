package nfqdatapath

import (
	"encoding/binary"

	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
	"go.uber.org/zap"
)

// HandshakeVersion is the enforcer version
// TODO: Enable this in datapath
const HandshakeVersion = 0x40

// ClaimsHeader holds header sub attributes
type ClaimsHeader struct {
	// CompressionType represents compressed tag mode attribute
	CompressionType uint8
	// Encrypt represents enryption enabled attribute
	Encrypt uint8
	// Handshake type represents handshake version
	HandshakeType uint8
}

// GenerateClaimsHeader generates the 32-bit header field
// claimsHeader holds all the claimsHeader sub attributes
func GenerateClaimsHeader(claimsHeader ClaimsHeader) []byte {

	// This is a 32 bit header used to be a symmetric identification between enforcers
	// Byte 0 : Bits 0,1 represents compressed tag mode.
	//          Bit 2 represents enryption enabled.
	//          Bits [3:6] represents handshake version.
	//          Bits [7] reserved for future use. (currently unused).
	// Bytes [1:3]: reserved for future use.

	claimsHeaderData := make([]byte, tokens.MaxHeaderLen)
	claimsHeaderData[0] |= claimsHeader.CompressionType
	claimsHeaderData[0] |= claimsHeader.Encrypt
	claimsHeaderData[0] |= claimsHeader.HandshakeType

	return claimsHeaderData
}

// CompareClaimsHeaderAttribute compares the given version attribute
// with the given 32-bit claims header field.
// claimsHeader is the complete 32-bit version field
// claimsHeaderAttr is the version sub attribute
// mask is the bit comparison
func CompareClaimsHeaderAttribute(claimsHeader []byte, claimsHeaderAttr uint8, mask uint8) bool {

	// check if the set claims header attribute is NOT the given claims header attribute and return false
	if parseClaimsHeaderAttr(claimsHeader, mask) != claimsHeaderAttr {
		zap.L().Debug("ClaimsHeader doesn't match",
			zap.String("cliamsHeader", string(claimsHeader)),
			zap.String("claimsHeaderAttribute", string(claimsHeaderAttr)))

		return false
	}

	return true
}

// parseClaimsHeaderAttr returns the claimsHeader attribute set
func parseClaimsHeaderAttr(claimsHeader []byte, mask uint8) uint8 {

	data := binary.LittleEndian.Uint16(claimsHeader)

	return uint8(data) & mask
}

func encryptionAttr(encrypt bool) uint8 {

	if !encrypt {
		return 0x00
	}

	return tokens.EncryptionEnabledMask
}
