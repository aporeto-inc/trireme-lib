package policy

// A RuntimeGetter allows to get the specific parameters stored in the Runtime
type RuntimeGetter interface {
	Pid() int
	Name() string
	Tag(string) (string, bool)
	Tags() TagMap
	DefaultIPAddress() (string, bool)
	IPAddresses() map[string]string
}
