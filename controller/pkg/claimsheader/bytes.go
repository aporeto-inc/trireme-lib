package claimsheader

import (
	"encoding/binary"


)

// HeaderBytes is the claimsheader in bytes
type HeaderBytes []byte

// ToClaimsHeader parses the bytes and returns the ClaimsHeader
// WARNING: Caller has to make sure that headerbytes is NOT nil
func (c HeaderBytes) ToClaimsHeader() *ClaimsHeader {

	return &ClaimsHeader{
		compressionType:  compressionTypeMask(c.extractHeaderAttribute(compressionTypeBitMask.ToUint8())),
		encrypt:          uint8ToBool(c.extractHeaderAttribute(EncryptionEnabledMask)),
		handshakeVersion: c.extractHeaderAttribute(HandshakeVersion),
	}
}

// extractHeaderAttribute returns the attribute from bytes
func (c HeaderBytes) extractHeaderAttribute(mask uint8) uint8 {

	data := binary.LittleEndian.Uint16(c)

	return uint8(data) & mask
}
