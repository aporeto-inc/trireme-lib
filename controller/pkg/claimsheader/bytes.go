package claimsheader

import (
	"encoding/binary"

	"go.aporeto.io/trireme-lib/controller/constants"
)

// HeaderBytes is the claimsheader in bytes
type HeaderBytes []byte

// ToClaimsHeader parses the bytes and returns the ClaimsHeader
// WARNING: Caller has to make sure that headerbytes is NOT nil
func (c HeaderBytes) ToClaimsHeader() *ClaimsHeader {

	return &ClaimsHeader{
		compressionType:  constants.CompressionTypeMask(c.extractHeaderAttribute(constants.CompressionTypeBitMask.ToUint8())),
		encrypt:          uint8ToBool(c.extractHeaderAttribute(EncryptionEnabledMask)),
		handshakeVersion: c.extractHeaderAttribute(HandshakeVersion),
	}
}

// extractHeaderAttribute returns the claimsHeader attribute set
func (c HeaderBytes) extractHeaderAttribute(mask uint8) uint8 {

	data := binary.LittleEndian.Uint16(c)

	return uint8(data) & mask
}
