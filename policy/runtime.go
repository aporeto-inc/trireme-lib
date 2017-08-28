package policy

import (
	"encoding/json"
	"sync"

	"github.com/aporeto-inc/trireme/constants"
)

// PURuntime holds all data related to the status of the container run time
type PURuntime struct {
	// puType is the type of the PU (container or process )
	puType constants.PUType
	// Pid holds the value of the first process of the container
	pid int
	// NsPath is the path to the networking namespace for this PURuntime if applicable.
	nsPath string
	// Name is the name of the container
	name string
	// IPAddress is the IP Address of the container
	ips ExtendedMap
	// Tags is a map of the metadata of the container
	tags *TagStore
	// options
	options ExtendedMap

	// GlobalLock is used by Trireme to make sure that two operations do not
	// get interleaved for the same container.
	GlobalLock *sync.Mutex

	sync.Mutex
}

// PURuntimeJSON is a Json representation of PURuntime
type PURuntimeJSON struct {
	// PUType is the type of the PU
	PUType constants.PUType
	// Pid holds the value of the first process of the container
	Pid int
	// NSPath is the path to the networking namespace for this PURuntime if applicable.
	NSPath string
	// Name is the name of the container
	Name string
	// IPAddress is the IP Address of the container
	IPAddresses ExtendedMap
	// Tags is a map of the metadata of the container
	Tags *TagStore
	// Options is a map of the options of the container
	Options ExtendedMap
}

// NewPURuntime Generate a new RuntimeInfo
func NewPURuntime(name string, pid int, nsPath string, tags *TagStore, ips ExtendedMap, puType constants.PUType, options ExtendedMap) *PURuntime {

	t := tags
	if t == nil {
		t = NewTagStore()
	}

	i := ips
	if i == nil {
		i = ExtendedMap{}
	}

	o := options
	if o == nil {
		o = ExtendedMap{}
	}

	return &PURuntime{
		puType:     puType,
		tags:       t,
		ips:        i,
		options:    o,
		pid:        pid,
		nsPath:     nsPath,
		name:       name,
		GlobalLock: &sync.Mutex{},
	}
}

// NewPURuntimeWithDefaults sets up PURuntime with defaults
func NewPURuntimeWithDefaults() *PURuntime {

	return NewPURuntime("", 0, "", nil, nil, constants.ContainerPU, nil)
}

// Clone returns a copy of the policy
func (r *PURuntime) Clone() *PURuntime {
	r.Lock()
	defer r.Unlock()

	return NewPURuntime(r.name, r.pid, r.nsPath, r.tags.Copy(), r.ips.Copy(), r.puType, r.options)
}

// MarshalJSON Marshals this struct.
func (r *PURuntime) MarshalJSON() ([]byte, error) {
	return json.Marshal(&PURuntimeJSON{
		PUType:      r.puType,
		Pid:         r.pid,
		NSPath:      r.nsPath,
		Name:        r.name,
		IPAddresses: r.ips,
		Tags:        r.tags,
		Options:     r.options,
	})
}

// UnmarshalJSON Unmarshals this struct.
func (r *PURuntime) UnmarshalJSON(param []byte) error {
	a := &PURuntimeJSON{}
	if err := json.Unmarshal(param, &a); err != nil {
		return err
	}
	r.pid = a.Pid
	r.nsPath = a.NSPath
	r.name = a.Name
	r.ips = a.IPAddresses
	r.tags = a.Tags
	r.options = a.Options
	r.puType = a.PUType
	return nil
}

// Pid returns the PID
func (r *PURuntime) Pid() int {
	r.Lock()
	defer r.Unlock()

	return r.pid
}

// SetPid sets the PID
func (r *PURuntime) SetPid(pid int) {
	r.Lock()
	defer r.Unlock()

	r.pid = pid
}

// NSPath returns the NSPath
func (r *PURuntime) NSPath() string {
	r.Lock()
	defer r.Unlock()

	return r.nsPath
}

// SetNSPath sets the NSPath
func (r *PURuntime) SetNSPath(nsPath string) {
	r.Lock()
	defer r.Unlock()

	r.nsPath = nsPath
}

// SetPUType sets the PU Type
func (r *PURuntime) SetPUType(puType constants.PUType) {
	r.Lock()
	defer r.Unlock()

	r.puType = puType
}

// SetOptions sets the Options
func (r *PURuntime) SetOptions(options ExtendedMap) {
	r.Lock()
	defer r.Unlock()

	r.options = options.Copy()
}

// Name returns the PID
func (r *PURuntime) Name() string {
	r.Lock()
	defer r.Unlock()

	return r.name
}

// PUType returns the PU type
func (r *PURuntime) PUType() constants.PUType {
	r.Lock()
	defer r.Unlock()

	return r.puType
}

// DefaultIPAddress returns the default IP address for the processing unit
func (r *PURuntime) DefaultIPAddress() (string, bool) {
	r.Lock()
	defer r.Unlock()

	ip, ok := r.ips[DefaultNamespace]

	return ip, ok
}

// IPAddresses returns all the IP addresses for the processing unit
func (r *PURuntime) IPAddresses() ExtendedMap {
	r.Lock()
	defer r.Unlock()

	return r.ips.Copy()
}

// SetIPAddresses sets up all the IP addresses for the processing unit
func (r *PURuntime) SetIPAddresses(ipa ExtendedMap) {
	r.Lock()
	defer r.Unlock()

	r.ips = ipa.Copy()
}

// Tag returns a specific tag for the processing unit
func (r *PURuntime) Tag(key string) (string, bool) {
	r.Lock()
	defer r.Unlock()

	tag, ok := r.tags.Get(key)
	return tag, ok
}

//Tags returns tags for the processing unit
func (r *PURuntime) Tags() *TagStore {
	r.Lock()
	defer r.Unlock()

	return r.tags.Copy()
}

// Options returns tags for the processing unit
func (r *PURuntime) Options() ExtendedMap {
	r.Lock()
	defer r.Unlock()

	return r.options.Copy()
}
