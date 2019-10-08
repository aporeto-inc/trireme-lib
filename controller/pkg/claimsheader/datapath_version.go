package claimsheader

// DatapathVersion defines the datapath version
type DatapathVersion int

// DatapathVersion constants
const (
	DatapathVersion1 DatapathVersion = iota
	DatapathVersion2
)

func (dv DatapathVersion) toMask() datapathVersionMask { // nolint

	if dv == DatapathVersion1 {
		return datapathVersion
	}

	return 0x00
}

// datapathVersion is the enforcer version
// TODO: Enable this in datapath
type datapathVersionMask uint8

const (
	datapathVersion        datapathVersionMask = 0x00
	datapathVersionBitMask datapathVersionMask = 0x3F
)

func (dm datapathVersionMask) toType() DatapathVersion {

	if dm == datapathVersion {
		return DatapathVersion1
	}

	return -1
}

// toUint8 returns uint8 from datapathVersionMask
func (dm datapathVersionMask) toUint8() uint8 {

	return uint8(dm)
}

// toUint8 returns uint8 from datapathVersionMask
func (dm datapathVersionMask) toUint32() uint32 {

	return uint32(dm)
}
