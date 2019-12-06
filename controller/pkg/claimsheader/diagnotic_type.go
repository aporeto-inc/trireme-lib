package claimsheader

// DiagnosticType defines the diagnostic type.
type DiagnosticType int

const (
	DiagnosticTypeNone DiagnosticType = iota
	DiagnosticTypeAporetoIdentity
	DiagnosticTypeCustomIdentity
	DiagnosticTypeAporetoIdentityPassthrough
)

// toMask returns the mask based on the type
func (dt DiagnosticType) toMask() diagnosticTypeMask {

	switch dt {
	case DiagnosticTypeNone:
		return diagnosticTypeNoneMask
	case DiagnosticTypeAporetoIdentity:
		return diagnosticTypeAporetoIdentityMask
	case DiagnosticTypeCustomIdentity:
		return diagnosticTypeCustomIdentityMask
	case DiagnosticTypeAporetoIdentityPassthrough:
		return diagnosticTypeAporetoIdentityPassthroughMask
	default:
		return diagnosticTypeNoneMask
	}
}

// toMask returns the mask based on the type
func (dt DiagnosticType) String() string {

	switch dt {
	case DiagnosticTypeNone:
		return "None"
	case DiagnosticTypeAporetoIdentity:
		return "AporetoIdentity"
	case DiagnosticTypeCustomIdentity:
		return "CustomIdentity"
	case DiagnosticTypeAporetoIdentityPassthrough:
		return "AporetoIdentityPassthrough"
	default:
		return "None"
	}
}

// diagnosticTypeMask defines the compression mask.
type diagnosticTypeMask uint8

const (
	// diagnosticTypeNoneMask mask that identifies compression type none
	diagnosticTypeNoneMask diagnosticTypeMask = 0x02
	// diagnosticTypeTokenMask mask that identifies compression type v1
	diagnosticTypeAporetoIdentityMask diagnosticTypeMask = 0x04
	// diagnosticTypeTokenMask mask that identifies compression type v1
	diagnosticTypeCustomIdentityMask diagnosticTypeMask = 0x06
	// diagnosticTypeTokenMask mask that identifies compression type v1
	diagnosticTypeAporetoIdentityPassthroughMask diagnosticTypeMask = 0x08
	// diagnosticTypeBitMask mask that identifies compression type v1
	diagnosticTypeBitMask diagnosticTypeMask = 0x3E
)

// toType returns the type based on mask
func (dm diagnosticTypeMask) toType() DiagnosticType {

	switch dm {
	case diagnosticTypeNoneMask:
		return DiagnosticTypeNone
	case diagnosticTypeAporetoIdentityMask:
		return DiagnosticTypeAporetoIdentity
	case diagnosticTypeCustomIdentityMask:
		return DiagnosticTypeCustomIdentity
	case diagnosticTypeAporetoIdentityPassthroughMask:
		return DiagnosticTypeAporetoIdentityPassthrough
	default:
		return DiagnosticTypeNone
	}
}

// toUint8 returns uint8 from DiagnosticTypemask
func (cm diagnosticTypeMask) toUint8() uint8 {

	return uint8(cm)
}
