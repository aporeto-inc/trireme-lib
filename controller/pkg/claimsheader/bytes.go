package claimsheader

// HeaderBytes is the claimsheader in bytes
type HeaderBytes []byte

// ToClaimsHeader parses the bytes and returns the ClaimsHeader
func (h HeaderBytes) ToClaimsHeader() *ClaimsHeader {

	if h == nil || len(h) != maxHeaderLen {
		return NewClaimsHeader()
	}

	compressionTypeMask := compressionTypeMask(h.extractHeaderAttribute(h[0], compressionTypeBitMask.toUint8()))
	datapathVersionMask := datapathVersionMask(h.extractHeaderAttribute(h[0], datapathVersionBitMask.toUint8()))

	return &ClaimsHeader{
		compressionType: compressionTypeMask.toType(),
		encrypt:         uint8ToBool(encrypt, h.extractHeaderAttribute(h[1], encryptionEnabledBit)),
		ping:            uint8ToBool(ping, h.extractHeaderAttribute(h[1], pingEnabledBit)),
		datapathVersion: datapathVersionMask.toType(),
	}
}

// extractHeaderAttribute returns the attribute from byte
// mask - mask specific to the attribute
func (h HeaderBytes) extractHeaderAttribute(attr byte, mask uint8) uint8 {

	return attr & mask
}
