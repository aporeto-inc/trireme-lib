package claimsheader

// PingType defines the ping type.
type PingType int

const (
	PingTypeNone PingType = iota
	PingTypeDefaultIdentity
	PingTypeCustomIdentity
	PingTypeDefaultIdentityPassthrough
)

// toMask returns the mask based on the type
func (dt PingType) toMask() pingTypeMask {

	switch dt {
	case PingTypeNone:
		return pingTypeNoneMask
	case PingTypeDefaultIdentity:
		return pingTypeDefaultIdentityMask
	case PingTypeCustomIdentity:
		return pingTypeCustomIdentityMask
	case PingTypeDefaultIdentityPassthrough:
		return pingTypeDefaultIdentityPassthroughMask
	default:
		return pingTypeNoneMask
	}
}

// toMask returns the mask based on the type
func (dt PingType) String() string {

	switch dt {
	case PingTypeNone:
		return "None"
	case PingTypeDefaultIdentity:
		return "DefaultIdentity"
	case PingTypeCustomIdentity:
		return "CustomIdentity"
	case PingTypeDefaultIdentityPassthrough:
		return "DefaultIdentityPassthrough"
	default:
		return "None"
	}
}

// pingTypeMask defines the ping type mask.
type pingTypeMask uint8

const (
	pingTypeNoneMask                       pingTypeMask = 0x02
	pingTypeDefaultIdentityMask            pingTypeMask = 0x04
	pingTypeCustomIdentityMask             pingTypeMask = 0x06
	pingTypeDefaultIdentityPassthroughMask pingTypeMask = 0x08
	pingTypeBitMask                        pingTypeMask = 0x3E
)

// toType returns the type based on mask
func (dm pingTypeMask) toType() PingType {

	switch dm {
	case pingTypeNoneMask:
		return PingTypeNone
	case pingTypeDefaultIdentityMask:
		return PingTypeDefaultIdentity
	case pingTypeCustomIdentityMask:
		return PingTypeCustomIdentity
	case pingTypeDefaultIdentityPassthroughMask:
		return PingTypeDefaultIdentityPassthrough
	default:
		return PingTypeNone
	}
}

// toUint8 returns uint8 from PingTypemask
func (cm pingTypeMask) toUint8() uint8 {

	return uint8(cm)
}
