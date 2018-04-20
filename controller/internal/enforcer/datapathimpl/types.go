package datapathimpl

type ImplType int

const (
	// DatapathTypeInvalid Invalid type
	DatapathTypeInvalid ImplType = iota
	// DatapathTypeNfqueue the datapath implementation is nfqueue based
	DatapathTypeNfqueue = 1
	// DatapathTypeTun the datapath implementation is tun interface based
	DatapathTypeTun = 2
	// DatapathTypeMax delimiter for max datapath type
	DatapathTypeMax
)
