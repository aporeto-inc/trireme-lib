package claimsheader



// NewClaimsHeader returns claims header handler
func NewClaimsHeader(opts ...Option) *ClaimsHeader {

	c := &ClaimsHeader{}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// ToBytes generates the 32-bit header in bytes
//    0             1              2               3               4
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |CT|E|  H    |                 R (reserved)                     |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  CT [0,1]  - Compressed tag type
//  E  [2]    - Enryption enabled
//  H  [3:6]  - Handshake version
//  R  [4:31] - Unused currently
func (c *ClaimsHeader) ToBytes() HeaderBytes {

	claimsHeaderData := make([]byte, MaxHeaderLen)
	claimsHeaderData[0] |= c.compressionType.ToUint8()
	claimsHeaderData[0] |= boolToUint8(c.encrypt)
	claimsHeaderData[0] |= c.handshakeVersion

	return claimsHeaderData
}

// CompressionType is the compression type
func (c *ClaimsHeader) CompressionType() CompressionType {

	return c.compressionType.compressionMaskToType()
}

// Encrypt is the encrypt in bool
func (c *ClaimsHeader) Encrypt() bool {

	return c.encrypt
}

// HandshakeVersion is the handshake version
func (c *ClaimsHeader) HandshakeVersion() uint8 {

	return c.handshakeVersion
}
