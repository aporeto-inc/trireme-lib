package claimsheader

import (
	"encoding/binary"
)

// HeaderBytes is the claimsheader in bytes
type HeaderBytes []byte

// ToClaimsHeader parses the bytes and returns the ClaimsHeader
// WARNING: Caller has to make sure that headerbytes is NOT nil
func (c HeaderBytes) ToClaimsHeader() *ClaimsHeader {

	compressionTypeMask := compressionTypeMask(c.extractHeaderAttribute(compressionTypeBitMask.toUint32()))
	datapathVersionMask := datapathVersionMask(c.extractHeaderAttribute(datapathVersionBitMask.toUint32()))

	return &ClaimsHeader{
		compressionType: compressionTypeMask.toType(),
		encrypt:         uint32ToBool(c.extractHeaderAttribute(encryptionEnabledMask)),
		datapathVersion: datapathVersionMask.toType(),
	}
}

// extractHeaderAttribute returns the attribute from bytes
// mask - mask specific to the attribute
func (c HeaderBytes) extractHeaderAttribute(mask uint32) uint32 {

	data := binary.LittleEndian.Uint32(c)

	return data & mask
}
