package policy

// A RuntimeGetter allows to get the specific parameters stored in the Runtime
type RuntimeGetter interface {

	// Pid returns the Pid of the Runtime.
	Pid() int

	// Name returns the process name of the Runtime.
	Name() string

	// Tag retuns the value of the given tag.
	Tag(string) (string, bool)

	// Tags returns the list of the tags.
	Tags() TagMap

	// DefaultIPAddress retutns the default IP address.
	DefaultIPAddress() (string, bool)

	// IPAddresses returns all the IP addresses.
	IPAddresses() map[string]string
}
