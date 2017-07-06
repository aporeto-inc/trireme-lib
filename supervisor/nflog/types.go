package nflog

// HalfIPStats TODO
type HalfIPStats struct {
	Bytes   int64
	Packets int64
}

// IPStats TODO
type IPStats struct {
	Source HalfIPStats
	Dest   HalfIPStats
}

// IPMap TODO
type IPMap map[string]*IPStats

// Packet holds the info about one packet
//
// Addr is a net.IP which is a []byte converted into a string This
// won't be a nice UTF-8 string but will preserve the bytes and can be
// used as a hash key
type Packet struct {
	Direction IPDirection
	Addr      string
	Length    int
}
