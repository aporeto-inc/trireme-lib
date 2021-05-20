package policy

import (
	"encoding/json"
	"sync"

	"github.com/docker/go-connections/nat"
	"go.aporeto.io/enforcerd/trireme-lib/common"
)

// PURuntime holds all data related to the status of the container run time
type PURuntime struct {
	// puType is the type of the PU (container or process )
	puType common.PUType
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
	options *OptionsType
	// ServiceMeshType determines which serviceMesh is enabled ont he pod
	ServiceMeshType ServiceMesh

	sync.Mutex
}

// PURuntimeJSON is a Json representation of PURuntime
type PURuntimeJSON struct {
	// PUType is the type of the PU
	PUType common.PUType
	// Pid holds the value of the first process of the container
	Pid int
	// NSPath is the path to the networking namespace for this PURuntime if applicable.
	NSPath string
	// Name is the name of the container
	Name string
	// IPAddress is the IP Address of the container
	IPAddresses ExtendedMap
	// Tags is a map of the metadata of the container
	Tags []string
	// Options is a map of the options of the container
	Options *OptionsType
}

// NewPURuntime Generate a new RuntimeInfo
func NewPURuntime(
	name string, pid int, nsPath string, tags *TagStore,
	ips ExtendedMap, puType common.PUType, serviceMeshType ServiceMesh, options *OptionsType) *PURuntime {

	if tags == nil {
		tags = NewTagStore()
	}

	if ips == nil {
		ips = ExtendedMap{}
	}

	if options == nil {
		options = &OptionsType{}
	}

	return &PURuntime{
		puType:          puType,
		tags:            tags,
		ips:             ips,
		options:         options,
		pid:             pid,
		nsPath:          nsPath,
		name:            name,
		ServiceMeshType: serviceMeshType,
	}
}

// NewPURuntimeWithDefaults sets up PURuntime with defaults
func NewPURuntimeWithDefaults() *PURuntime {

	return NewPURuntime("", 0, "", nil, nil, common.ContainerPU, None, nil)
}

// Clone returns a copy of the policy
func (r *PURuntime) Clone() *PURuntime {
	r.Lock()
	defer r.Unlock()

	return NewPURuntime(r.name, r.pid, r.nsPath, r.tags.Copy(), r.ips.Copy(), r.puType, None, r.options)
}

// MarshalJSON Marshals this struct.
func (r *PURuntime) MarshalJSON() ([]byte, error) {
	return json.Marshal(&PURuntimeJSON{
		PUType:      r.puType,
		Pid:         r.pid,
		NSPath:      r.nsPath,
		Name:        r.name,
		IPAddresses: r.ips,
		Tags:        r.tags.GetSlice(),
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
	r.tags = NewTagStoreFromSlice(a.Tags)
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
func (r *PURuntime) SetPUType(puType common.PUType) {
	r.Lock()
	defer r.Unlock()

	r.puType = puType
}

// SetOptions sets the Options
func (r *PURuntime) SetOptions(options OptionsType) {
	r.Lock()
	defer r.Unlock()

	r.options = &options
}

// Name returns the PID
func (r *PURuntime) Name() string {
	r.Lock()
	defer r.Unlock()

	return r.name
}

// PUType returns the PU type
func (r *PURuntime) PUType() common.PUType {
	r.Lock()
	defer r.Unlock()

	return r.puType
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

// Tags returns a copy of the tags for the processing unit
func (r *PURuntime) Tags() *TagStore {
	r.Lock()
	defer r.Unlock()

	return r.tags.Copy()
}

// SetTags returns tags for the processing unit
func (r *PURuntime) SetTags(t *TagStore) {
	r.Lock()
	defer r.Unlock()

	r.tags = t.Copy()
}

// Options returns tags for the processing unit
func (r *PURuntime) Options() OptionsType {
	r.Lock()
	defer r.Unlock()

	r.ensureOptions()

	return *r.options
}

// SetServices updates the services of the runtime.
func (r *PURuntime) SetServices(services []common.Service) {
	r.Lock()
	defer r.Unlock()

	r.ensureOptions()

	r.options.Services = services
}

// PortMap returns the mapping from host port->container port
func (r *PURuntime) PortMap() map[nat.Port][]string {
	r.Lock()
	defer r.Unlock()

	if r.options != nil {
		return r.options.PortMap
	}

	return nil
}

func (r *PURuntime) ensureOptions() {
	if r.options == nil {
		r.options = &OptionsType{}
	}
}
