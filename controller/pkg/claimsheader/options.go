package claimsheader

// Option is used to set claimsheader fields
type Option func(*ClaimsHeader)

// OptionCompressionType sets compression Type
func OptionCompressionType(compressionType CompressionType) Option {

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

// OptionDatapathVersion sets handshake version
func OptionDatapathVersion(datapathVersion DatapathVersion) Option {

	return func(c *ClaimsHeader) {
		c.datapathVersion = datapathVersion
	}
}
