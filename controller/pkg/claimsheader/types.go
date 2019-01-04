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

// Encrypt type bool
type Encrypt bool

// ToUint8 returns the encrypt uint8 based on the flag
func (e Encrypt) ToUint8() uint8 {

	if !e {
		return 0x00
	}

	return EncryptionEnabledMask
}

func Uint8ToBool(n uint8) bool {

	if n == 0x00 {
		return false
	}

	return true
}
