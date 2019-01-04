package claimsheader

// Option is used to set claimsheader fields
type Option func(*ClaimsHeader)

// OptionCompressionType sets compression Type
func OptionCompressionType(compressionType CompressionTypeMask) Option {

	return func(c *ClaimsHeader) {
		c.compressionType = compressionType
	}
}

// OptionEncrypt sets encryption
func OptionEncrypt(encrypt bool) Option {

	return func(c *ClaimsHeader) {
		c.encrypt = encrypt
	}
}

// OptionHandshakeVersion sets handshake version
func OptionHandshakeVersion(handshakeVersion uint8) Option {

	return func(c *ClaimsHeader) {
		c.handshakeVersion = handshakeVersion
	}
}
