package claimsheader

// CompressionType defines the compression used.
type CompressionType string

const (
	// CompressionTypeNone implies no compression
	CompressionTypeNone CompressionType = ""
	// CompressionTypeV1 is version 1 of compression
	CompressionTypeV1 CompressionType = "1"
	// CompressionTypeV2 is version 2 of compression
	CompressionTypeV2 CompressionType = "2"
)

const (
	// CompressedTagLengthV1 is version 1 length of tags
	CompressedTagLengthV1 int = 12

	// CompressedTagLengthV2 is version 2 length of tags
	CompressedTagLengthV2 int = 4
)

// CompressionTypeMask defines the compression mask.
type CompressionTypeMask uint8

const (
	// CompressionTypeNoneMask mask that identifies compression type none
	CompressionTypeNoneMask CompressionTypeMask = 0x00
	// CompressionTypeV1Mask mask that identifies compression type v1
	CompressionTypeV1Mask CompressionTypeMask = 0x01
	// CompressionTypeV2Mask mask that identifies compression type v2
	CompressionTypeV2Mask CompressionTypeMask = 0x02
	// CompressionTypeMask mask used to check relevant compression types
	CompressionTypeBitMask CompressionTypeMask = 0x03
)

// CompressionTypeToMask returns the mask based on the type
func (ct CompressionType) CompressionTypeToMask() CompressionTypeMask {

	switch ct {
	case CompressionTypeV1:
		return CompressionTypeV1Mask
	case CompressionTypeV2:
		return CompressionTypeV2Mask
	default:
		return CompressionTypeNoneMask
	}
}

// CompressionTypeToMask returns the mask based on the type
func (cm CompressionTypeMask) CompressionMaskToType() CompressionType {

	switch cm {
	case CompressionTypeV1Mask:
		return CompressionTypeV1
	case CompressionTypeV2Mask:
		return CompressionTypeV2
	default:
		return CompressionTypeNone
	}
}

// CompressionTypeToMask returns the mask based on the type
func (cm CompressionTypeMask) ToUint8() uint8 {

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

// API service related constants
const (
	CallbackURIExtension = "/aporeto/oidc/callback"
)
