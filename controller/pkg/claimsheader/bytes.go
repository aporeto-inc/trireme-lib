package claimsheader

import (
	"encoding/binary"

	"go.aporeto.io/trireme-lib/controller/constants"
)

// HeaderBytess is the bytes returned
type HeaderBytes []byte

// ToClaimsHeader parses the bytes and returns the ClaimsHeader
func (c HeaderBytes) ToClaimsHeader() *ClaimsHeader {

	claimsHeader := ClaimsHeader{}
	claimsHeader.compressionType = constants.CompressionTypeMask(c.parseClaimsHeaderAttr(constants.CompressionTypeBitMask.ToUint8()))
	claimsHeader.encrypt = Uint8ToBool(c.parseClaimsHeaderAttr(EncryptionEnabledMask))
	claimsHeader.handshakeVersion = c.parseClaimsHeaderAttr(HandshakeVersion)

	return &claimsHeader
}

// parseClaimsHeaderAttr returns the claimsHeader attribute set
func (c HeaderBytes) parseClaimsHeaderAttr(mask uint8) uint8 {

	data := binary.LittleEndian.Uint16(c)

	return uint8(data) & mask
}
