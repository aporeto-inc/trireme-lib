package portset

// UserManipulator provides a manipulator interface
// to update  add/delete users to portset mappings.
type UserManipulator interface {
	AddUserPortSet(userName string, portset string, mark string) (err error)
	DelUserPortSet(userName string, mark string) error
	getUserPortSet(userName string) (string, error)

	GetUserMark(mark string) (string, error)
}

// PortManipulator provides a manipulator interface
// to update user to port mappings.
type PortManipulator interface {
	AddPortToUser(userName string, port string) (bool, error)
}

// PortSet provides an interface to update the
// mappings required to program the ipset portsets.
type PortSet interface {
	UserManipulator

	PortManipulator

	addPortSet(userName string, port string) error
	deletePortSet(userName string, port string) error
}
