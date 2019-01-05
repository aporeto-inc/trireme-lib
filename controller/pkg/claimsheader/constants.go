package claimsheader

const (
	// maxHeaderLen must be maximimum claims header length
	maxHeaderLen = 4
	// encryptionEnabledBit that is set in the bytes
	encryptionEnabledBit = 0x01
	// encryptionEnabledMask mask that is the decimal value of the bit
	encryptionEnabledMask = 0x100
)
