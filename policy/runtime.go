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
	//PURuntimeMutex is a mutex to prevent access to same runtime object from multiple threads
	puRuntimeMutex *sync.Mutex
	// Pid holds the value of the first process of the container
	pid int
	// Name is the name of the container
	name string
	// IPAddress is the IP Address of the container
	ips *IPMap
	// Tags is a map of the metadata of the container
	tags *TagsMap
	// options
	options *TagsMap
}

// PURuntimeJSON is a Json representation of PURuntime
type PURuntimeJSON struct {
	// PUType is the type of the PU
	PUType constants.PUType
	// Pid holds the value of the first process of the container
	Pid int
	// Name is the name of the container
	Name string
	// IPAddress is the IP Address of the container
	IPAddresses *IPMap
	// Tags is a map of the metadata of the container
	Tags *TagsMap
	// Options is a map of the options of the container
	Options *TagsMap
}

// NewPURuntime Generate a new RuntimeInfo
func NewPURuntime(name string, pid int, tags *TagsMap, ips *IPMap, puType constants.PUType, options *TagsMap) *PURuntime {

	t := tags
	if t == nil {
		t = NewTagsMap(nil)
	}

	i := ips
	if i == nil {
		i = NewIPMap(nil)
	}

	o := options
	if o == nil {
		o = NewTagsMap(nil)
	}

	return &PURuntime{
		puType:         puType,
		puRuntimeMutex: &sync.Mutex{},
		tags:           t,
		ips:            i,
		options:        o,
		pid:            pid,
		name:           name,
	}
}

// NewPURuntimeWithDefaults sets up PURuntime with defaults
func NewPURuntimeWithDefaults() *PURuntime {

	return NewPURuntime("", 0, nil, nil, constants.ContainerPU, nil)
}

// Clone returns a copy of the policy
func (r *PURuntime) Clone() *PURuntime {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	return NewPURuntime(r.name, r.pid, r.tags.Clone(), r.ips.Clone(), r.puType, r.options)
}

// MarshalJSON Marshals this struct.
func (r *PURuntime) MarshalJSON() ([]byte, error) {
	return json.Marshal(&PURuntimeJSON{
		PUType:      r.puType,
		Pid:         r.pid,
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
	r.name = a.Name
	r.ips = a.IPAddresses
	r.tags = a.Tags
	r.options = a.Options
	r.puType = a.PUType
	return nil
}

// Pid returns the PID
func (r *PURuntime) Pid() int {
	return r.pid
}

// SetPid sets the PID
func (r *PURuntime) SetPid(pid int) {
	r.pid = pid
}

// SetPUType sets the PU Type
func (r *PURuntime) SetPUType(puType constants.PUType) {
	r.puType = puType
}

// SetOptions sets the Options
func (r *PURuntime) SetOptions(options *TagsMap) {
	r.options = options
}

// Name returns the PID
func (r *PURuntime) Name() string {
	return r.name
}

// PUType returns the PU type
func (r *PURuntime) PUType() constants.PUType {
	return r.puType
}

// DefaultIPAddress returns the default IP address for the processing unit
func (r *PURuntime) DefaultIPAddress() (string, bool) {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	ip, ok := r.ips.Get("bridge")

	return ip, ok
}

// IPAddresses returns all the IP addresses for the processing unit
func (r *PURuntime) IPAddresses() *IPMap {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	return r.ips.Clone()
}

// SetIPAddresses sets up all the IP addresses for the processing unit
func (r *PURuntime) SetIPAddresses(ipa *IPMap) {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	r.ips = ipa.Clone()
}

//Tag returns a specific tag for the processing unit
func (r *PURuntime) Tag(key string) (string, bool) {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	tag, ok := r.tags.Get(key)
	return tag, ok
}

//Tags returns tags for the processing unit
func (r *PURuntime) Tags() *TagsMap {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	return r.tags.Clone()
}

// Options returns tags for the processing unit
func (r *PURuntime) Options() *TagsMap {
	r.puRuntimeMutex.Lock()
	defer r.puRuntimeMutex.Unlock()

	return r.options.Clone()
}
