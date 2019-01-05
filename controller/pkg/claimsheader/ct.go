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
