package claimsheader

// NewClaimsHeader returns claims header handler
func NewClaimsHeader(opts ...Option) *ClaimsHeader {

	c := &ClaimsHeader{}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// ToByte generates the 32-bit header field
// claimsHeader holds all the claimsHeader sub attributes
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

func (c *ClaimsHeader) CompressionType() CompressionType {

	return c.compressionType.CompressionMaskToType()
}

func (c *ClaimsHeader) Encrypt() bool {

	return bool(c.encrypt)
}

func (c *ClaimsHeader) HandshakeVersion() uint8 {

	return HandshakeVersion
}
