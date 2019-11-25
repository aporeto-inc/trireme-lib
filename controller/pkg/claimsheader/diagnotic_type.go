package claimsheader

// DiagnosticType defines the diagnostic type.
type DiagnosticType int

const (
	DiagnosticTypeNone DiagnosticType = iota
	DiagnosticTypeToken
)

// toMask returns the mask based on the type
func (dt DiagnosticType) toMask() diagnosticTypeMask {

	switch dt {
	case DiagnosticTypeNone:
		return diagnosticTypeNoneMask
	case DiagnosticTypeToken:
		return diagnosticTypeTokenMask
	default:
		return diagnosticTypeNoneMask
	}
}

// diagnosticTypeMask defines the compression mask.
type diagnosticTypeMask uint8

const (
	// diagnosticTypeNoneMask mask that identifies compression type none
	diagnosticTypeNoneMask diagnosticTypeMask = 0x02
	// diagnosticTypeTokenMask mask that identifies compression type v1
	diagnosticTypeTokenMask diagnosticTypeMask = 0x04
	// diagnosticTypeBitMask mask that identifies compression type v1
	diagnosticTypeBitMask diagnosticTypeMask = 0x3E
)

// toType returns the type based on mask
func (dm diagnosticTypeMask) toType() DiagnosticType {

	switch dm {
	case diagnosticTypeNoneMask:
		return DiagnosticTypeNone
	case diagnosticTypeTokenMask:
		return DiagnosticTypeToken
	default:
		return DiagnosticTypeNone
	}
}

// toUint8 returns uint8 from DiagnosticTypemask
func (cm diagnosticTypeMask) toUint8() uint8 {

	return uint8(cm)
}
