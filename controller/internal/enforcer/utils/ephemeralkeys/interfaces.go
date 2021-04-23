package ephemeralkeys

// KeyAccessor holds the ephemeral key functions
type KeyAccessor interface {
	PrivateKey() *PrivateKey
	DecodingKeyV1() []byte
	DecodingKeyV2() []byte
}
