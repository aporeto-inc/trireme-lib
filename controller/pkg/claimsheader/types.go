package claimsheader

import "go.aporeto.io/trireme-lib/controller/constants"

// ClaimsHeader holds header sub attributes
type ClaimsHeader struct {
	// CompressionType represents compressed tag mode attribute
	compressionType constants.CompressionTypeMask
	// Encrypt represents enryption enabled attribute
	encrypt bool
	// Handshake type represents handshake version
	handshakeVersion uint8
}

// boolToUint8 converts bool to uint8
func boolToUint8(e bool) uint8 {

	if !e {
		return 0x00
	}

	return EncryptionEnabledMask
}

// uint8ToBool converts uint8 to bool
func uint8ToBool(n uint8) bool {

	return n == EncryptionEnabledMask
}
