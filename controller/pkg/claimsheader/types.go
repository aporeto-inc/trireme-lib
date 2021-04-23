package claimsheader

// ClaimsHeader holds header sub attributes
type ClaimsHeader struct {
	// CompressionType represents compressed tag mode attribute
	compressionType CompressionType
	// Encrypt represents enryption enabled attribute
	encrypt bool
	// Handshake type represents datapath version
	datapathVersion DatapathVersion
	// Ping represents ping is set
	ping bool
}

type boolType int

const (
	encrypt boolType = iota
	ping
)

// boolToUint8 converts bool to uint8
// to populate the bits based on v
func boolToUint8(t boolType, v bool) uint8 {

	if !v {
		return zeroBit
	}

	switch t {
	case encrypt:
		return encryptionEnabledBit
	case ping:
		return pingEnabledBit
	default:
		return zeroBit
	}
}

// uint8ToBool converts uint8 to bool
// to populate the struct based on n
func uint8ToBool(t boolType, n uint8) bool {

	switch t {
	case encrypt:
		return n == encryptionEnabledBit
	case ping:
		return n == pingEnabledBit
	default:
		return false
	}
}
