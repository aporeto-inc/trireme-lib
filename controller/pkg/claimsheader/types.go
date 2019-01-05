package claimsheader

// ClaimsHeader holds header sub attributes
type ClaimsHeader struct {
	// CompressionType represents compressed tag mode attribute
	compressionType CompressionType
	// Encrypt represents enryption enabled attribute
	encrypt bool
	// Handshake type represents handshake version
	datapathVersion DatapathVersion
}

// boolToUint8 converts bool to uint8
func boolToUint8(e bool) uint8 {

	if !e {
		return 0x00
	}

	return encryptionEnabledBit
}

// uint32ToBool converts uint8 to bool
func uint32ToBool(n uint32) bool {

	return n == encryptionEnabledMask
}
