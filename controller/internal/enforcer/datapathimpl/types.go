package datapathimpl

type DatapathImplType int

const (
	DATAPATHIMPLTYPEINVALID DatapathImplType = iota
	NFQUEUE                                  = 1
	TUNDATAPATH                              = 2
	DATAPATHIMPLTYPEMAX
)
