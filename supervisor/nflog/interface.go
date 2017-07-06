package nflog

// NFLogger is the interface of a NFLog capable struct.
type NFLogger interface {
	Start()
	Stop()
}
