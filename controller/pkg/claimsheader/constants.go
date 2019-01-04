package claimsheader

const (
	// HandshakeVersion is the enforcer version
	// TODO: Enable this in datapath
	HandshakeVersion = 0x40
	// MaxHeaderLen must be maximimum claims header length
	MaxHeaderLen = 4
	// EncryptionEnabledMask mask that identifies the handshake version
	EncryptionEnabledMask = 0x04
)
