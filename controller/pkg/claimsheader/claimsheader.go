package claimsheader

import "go.aporeto.io/trireme-lib/controller/constants"

// NewClaimsHeader returns claims header handler
func NewClaimsHeader(opts ...Option) *ClaimsHeader {

	c := &ClaimsHeader{}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// ToBytes generates the 32-bit header in bytes
func (c *ClaimsHeader) ToBytes() HeaderBytes {

	// This is a 32 bit header used to be a symmetric identification between enforcers
	// Byte 0 : Bits 0,1 represents compressed tag mode.
	//          Bit 2 represents enryption enabled.
	//          Bits [3:6] represents handshake version.
	//          Bits [7] reserved for future use. (currently unused).
	// Bytes [1:3]: reserved for future use.

	claimsHeaderData := make([]byte, MaxHeaderLen)
	claimsHeaderData[0] |= c.compressionType.ToUint8()
	claimsHeaderData[0] |= Encrypt(c.encrypt).ToUint8()
	claimsHeaderData[0] |= c.handshakeVersion

	return claimsHeaderData
}

// CompressionType is the compression type
func (c *ClaimsHeader) CompressionType() constants.CompressionType {

	return c.compressionType.CompressionMaskToType()
}

// Encrypt is the encrypt in bool
func (c *ClaimsHeader) Encrypt() bool {

	return bool(c.encrypt)
}

// HandshakeVersion is the handshake version
func (c *ClaimsHeader) HandshakeVersion() uint8 {

	return HandshakeVersion
}
