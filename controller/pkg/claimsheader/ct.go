package claimsheader

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
	CompressedTagLengthV2 int = 4
)

// compressionTypeMask defines the compression mask.
type compressionTypeMask uint8

const (
	// compressionTypeNoneMask mask that identifies compression type none
	compressionTypeNoneMask compressionTypeMask = 0x00
	// compressionTypeV1Mask mask that identifies compression type v1
	compressionTypeV1Mask compressionTypeMask = 0x01
	// compressionTypeV2Mask mask that identifies compression type v2
	compressionTypeV2Mask compressionTypeMask = 0x02
	// compressionTypeBitMask mask used to check relevant compression types
	compressionTypeBitMask compressionTypeMask = 0x03
)

// compressionTypeToMask returns the mask based on the type
func (ct CompressionType) compressionTypeToMask() compressionTypeMask {

	switch ct {
	case CompressionTypeV1:
		return compressionTypeV1Mask
	case CompressionTypeV2:
		return compressionTypeV2Mask
	default:
		return compressionTypeNoneMask
	}
}

// compressionMaskToType returns the type based on mask
func (cm compressionTypeMask) compressionMaskToType() CompressionType {

	switch cm {
	case compressionTypeV1Mask:
		return CompressionTypeV1
	case compressionTypeV2Mask:
		return CompressionTypeV2
	default:
		return CompressionTypeNone
	}
}

// ToUint8 returns uint8 from compressiontypemask
func (cm compressionTypeMask) ToUint8() uint8 {

	return uint8(cm)
}

// CompressionTypeToTagLength converts CompressionType to length.
func CompressionTypeToTagLength(t CompressionType) int {

	if t == CompressionTypeNone {
		return 0
	}

	if t == CompressionTypeV1 {
		return CompressedTagLengthV1
	}

	return CompressedTagLengthV2
}

// String2CompressionType is a helper to convert string to compression type
func String2CompressionType(s string) CompressionType {
	if s == string(CompressionTypeV1) {
		return CompressionTypeV1
	}
	if s == string(CompressionTypeV2) {
		return CompressionTypeV2
	}
	return CompressionTypeNone
}
