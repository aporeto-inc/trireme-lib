package claimsheader

// ClaimsHeader holds header sub attributes
type ClaimsHeader struct {
	// CompressionType represents compressed tag mode attribute
	compressionType CompressionType
	// Encrypt represents enryption enabled attribute
	encrypt bool
	// Handshake type represents datapath version
	datapathVersion DatapathVersion
	// oam represents oam packet
	oam bool
}

// boolToUint8 converts bool to uint8
// to populate the bits based on bool flags in c
func boolToUint8(b boolAttributes, e bool) uint8 {

	if !e {
		return zeroBit
	}

	switch b {
	case encryptAttr:
		return encryptionEnabledBit
	case oamAttr:
		return oamEnabledBit
	default:
		return zeroBit
	}
}

// uint32ToBool converts uint8 to bool
// to populate the struct based on bool
func uint32ToBool(b boolAttributes, n uint32) bool {

	switch b {
	case encryptAttr:
		return n == encryptionEnabledMask
	case oamAttr:
		return n == oamEnabledMask
	default:
		return false
	}
}
