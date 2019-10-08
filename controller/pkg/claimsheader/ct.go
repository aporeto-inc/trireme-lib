package claimsheader

import "strconv"

// CompressionType defines the compression used.
type CompressionType int

const (
	// CompressionTypeNone implies no compression
	CompressionTypeNone CompressionType = iota
	// CompressionTypeV1 is version 1 of compression
	CompressionTypeV1
	// CompressionTypeV2 is version 2 of compression
	CompressionTypeV2
)

const (
	// CompressedTagLengthV1 is version 1 length of tags
	CompressedTagLengthV1 int = 12

	// CompressedTagLengthV2 is version 2 length of tags
	CompressedTagLengthV2 int = 8
)

// toMask returns the mask based on the type
func (ct CompressionType) toMask() compressionTypeMask {

	switch ct {
	case CompressionTypeV1:
		return compressionTypeV1Mask
	case CompressionTypeV2:
		return compressionTypeV2Mask
	default:
		return compressionTypeNoneMask
	}
}

func (ct CompressionType) toString() string {

	return strconv.Itoa(int(ct))
}

// compressionTypeMask defines the compression mask.
type compressionTypeMask uint8

const (
	// compressionTypeNoneMask mask that identifies compression type none
	compressionTypeNoneMask compressionTypeMask = 0x40
	// compressionTypeV1Mask mask that identifies compression type v1
	compressionTypeV1Mask compressionTypeMask = 0x80
	// compressionTypeV2Mask mask that identifies compression type v2
	compressionTypeV2Mask compressionTypeMask = 0xC0
	// compressionTypeBitMask mask used to check relevant compression types
	compressionTypeBitMask compressionTypeMask = 0xC0
)

// toType returns the type based on mask
func (cm compressionTypeMask) toType() CompressionType {

	switch cm {
	case compressionTypeV1Mask:
		return CompressionTypeV1
	case compressionTypeV2Mask:
		return CompressionTypeV2
	default:
		return CompressionTypeNone
	}
}

// toUint8 returns uint8 from compressiontypemask
func (cm compressionTypeMask) toUint8() uint8 {

	return uint8(cm)
}

// toUint8 returns uint8 from compressiontypemask
func (cm compressionTypeMask) toUint32() uint32 {

	return uint32(cm)
}

// CompressionTypeToTagLength converts CompressionType to length.
func CompressionTypeToTagLength(t CompressionType) int {

	switch t {
	case CompressionTypeV2:
		return CompressedTagLengthV2
	default:
		return CompressedTagLengthV1
	}
}

// String2CompressionType is a helper to convert string to compression type
func String2CompressionType(s string) CompressionType {

	switch s {
	case CompressionTypeV1.toString():
		return CompressionTypeV1
	case CompressionTypeV2.toString():
		return CompressionTypeV2
	default:
		return CompressionTypeNone
	}
}
