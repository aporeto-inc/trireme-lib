package portset

// PortSet : This provides an interface to update the
// look up table required to program the ipset portsets.
type PortSet interface {
	AddToUIDPortSet(uid string, value string) (err error)
	GetFromUIDPortSet(uid string) (string, error)
	AddPortToUID(uid string, value string) (bool, error)
	DeleteFromUIDPortSet(uid string) error
	AddPortSet(uid string, port string) error
}
