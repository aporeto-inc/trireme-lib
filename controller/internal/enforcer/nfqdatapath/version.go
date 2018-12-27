package nfqdatapath

import (
	"fmt"

	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
	"go.uber.org/zap"
)

func GenerateVersion(compressionType uint8, encrypt bool) []byte {

	// This is a 32 bit version used to be a symmetric identification between enforcers
	// Byte 0 : Bits 0,1 represents compressed tag mode.
	//          Bit 2 represents enryption enabled.
	//          Bits [3:7] reserved for future use. (currently unused).
	// Bytes [1:3]: reserved for future use.

	version := make([]byte, tokens.MaxVersionLen)
	version[0] |= compressionType
	if encrypt {
		version[0] |= tokens.EncryptionEnabledMask
	}

	zap.L().Debug("META: Bit", zap.Reflect("bit", fmt.Sprintf("%08b", version)))
	return version
}

func CompareVersion(version []byte, versionType uint8, mask uint8) bool {

	if parseVersion(version, mask) != versionType {
		zap.L().Debug("META:  BIT IS NOT SET", zap.String("given", string(version)), zap.String("current", string(versionType)))
		return false
	}

	return true
}

func parseVersion(version []byte, versionType uint8) byte {
	zap.L().Debug("META:  Given version", zap.Reflect("version", string(version)))
	return version[0] & versionType
}
