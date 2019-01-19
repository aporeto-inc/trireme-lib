package claimsheader

// ClaimsHeader holds header sub attributes
type ClaimsHeader struct {
	// CompressionType represents compressed tag mode attribute
	compressionType CompressionType
	// Encrypt represents enryption enabled attribute
	encrypt bool
	// Handshake type represents datapath version
	datapathVersion DatapathVersion
}

// boolToUint8 converts bool to uint8
// to populate the bits based on e
func boolToUint8(e bool) uint8 {

	if !e {
		return 0x00
	}

	return encryptionEnabledBit
}

// uint32ToBool converts uint8 to bool
// to populate the struct based on n
func uint32ToBool(n uint32) bool {

	return n == encryptionEnabledMask
}
