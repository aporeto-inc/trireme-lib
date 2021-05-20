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
//  |     D     |CT |E|P|            R (reserved)                   |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  D  [0:5]   - Datapath version
//  CT [6,7]   - Compressed tag type
//  E  [8]     - Encryption enabled
//  P  [9]     - Ping enabled
//  R  [10:31] - Reserved
func (c *ClaimsHeader) ToBytes() HeaderBytes {

	claimsHeaderData := make([]byte, maxHeaderLen)
	claimsHeaderData[0] |= c.datapathVersion.toMask().toUint8()
	claimsHeaderData[0] |= c.compressionType.toMask().toUint8()
	claimsHeaderData[1] |= boolToUint8(encrypt, c.encrypt)
	claimsHeaderData[1] |= boolToUint8(ping, c.ping)

	return claimsHeaderData
}

// CompressionType is the compression type
func (c *ClaimsHeader) CompressionType() CompressionType {

	return c.compressionType
}

// Encrypt is the encrypt in bool
func (c *ClaimsHeader) Encrypt() bool {

	return c.encrypt
}

// DatapathVersion is the datapath version
func (c *ClaimsHeader) DatapathVersion() DatapathVersion {

	return c.datapathVersion
}

// Ping returns the ping in bool
func (c *ClaimsHeader) Ping() bool {

	return c.ping
}

// SetCompressionType sets the compression type
func (c *ClaimsHeader) SetCompressionType(ct CompressionType) {

	c.compressionType = ct
}

// SetEncrypt sets the encrypt
func (c *ClaimsHeader) SetEncrypt(e bool) {

	c.encrypt = e
}

// SetDatapathVersion sets the datapath version
func (c *ClaimsHeader) SetDatapathVersion(dv DatapathVersion) {

	c.datapathVersion = dv
}

// SetPing sets the ping
func (c *ClaimsHeader) SetPing(ping bool) {

	c.ping = ping
}
