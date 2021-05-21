package claimsheader

import "strconv"

// CompressionType defines the compression used.
type CompressionType int

const (

	// CompressionTypeV1 is version 1 of compression
	CompressionTypeV1 CompressionType = iota
)

const (
	// CompressedTagLengthV1 is version 1 length of tags
	CompressedTagLengthV1 int = 12

	// CompressedTagLengthV2 is version 2 length of tags
	CompressedTagLengthV2 int = 8
)

// toMask returns the mask based on the type
func (ct CompressionType) toMask() compressionTypeMask {

	return compressionTypeV1Mask

}

func (ct CompressionType) toString() string {

	return strconv.Itoa(int(ct))
}

// compressionTypeMask defines the compression mask.
type compressionTypeMask uint8

const (
	// compressionTypeV1Mask mask that identifies compression type v1
	compressionTypeV1Mask compressionTypeMask = 0x80
	// compressionTypeBitMask mask used to check relevant compression types
	compressionTypeBitMask compressionTypeMask = 0xC0
)

// toType returns the type based on mask
func (cm compressionTypeMask) toType() CompressionType {
	return CompressionTypeV1
}

// toUint8 returns uint8 from compressiontypemask
func (cm compressionTypeMask) toUint8() uint8 {

	return uint8(cm)
}

// CompressionTypeToTagLength converts CompressionType to length.
func CompressionTypeToTagLength(t CompressionType) int {

	return CompressedTagLengthV1

}

// String2CompressionType is a helper to convert string to compression type
func String2CompressionType(s string) CompressionType {

	return CompressionTypeV1

}
