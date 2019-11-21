package claimsheader

const (
	// maxHeaderLen must be maximimum claims header length
	maxHeaderLen = 4
	// zeroBit is the value 0
	zeroBit = 0x00
	// encryptionEnabledBit that is set in the bytes
	encryptionEnabledBit = 0x01
	// encryptionEnabledMask mask that is the decimal value of the bit
	encryptionEnabledMask = 0x100
	// oamEnabledBit that is set in the bytes
	oamEnabledBit = 0x02
	// oamEnabledMask mask that is the decimal value of the bit
	oamEnabledMask = 0x200
)

type boolAttributes int

const (
	encryptAttr boolAttributes = iota
	oamAttr
)
