package claimsheader

const (
	// maxHeaderLen must be maximimum claims header length
	maxHeaderLen = 4
	// zeroBit is the value 0
	zeroBit = 0x00
	// encryptionEnabledBit that is set in the bytes
	encryptionEnabledBit = 0x01
	// pingEnabledBit that is set in the bytes
	pingEnabledBit = 0x02
)
