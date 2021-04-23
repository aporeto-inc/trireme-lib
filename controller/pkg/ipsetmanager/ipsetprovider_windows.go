// +build windows

package ipsetmanager

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.aporeto.io/enforcerd/trireme-lib/utils/frontman"
)

// IpsetProvider returns a fabric for Ipset.
type IpsetProvider interface {
	NewIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error)
	GetIpset(name string) Ipset
	DestroyAll(prefix string) error
	ListIPSets() ([]string, error)
}

// Ipset is an abstraction of all the methods an implementation of userspace
// ipsets need to provide.
type Ipset interface {
	Add(entry string, timeout int) error
	AddOption(entry string, option string, timeout int) error
	Del(entry string) error
	Destroy() error
	Flush() error
	Test(entry string) (bool, error)
}

type ipsetProvider struct{}

var instance IpsetProvider = &ipsetProvider{}

type winIPSet struct {
	handle uintptr
	name   string
}

// NewIpset returns an IpsetProvider interface based on the go-ipset
// external package.
func (i *ipsetProvider) NewIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error) {
	ipsetHandle, err := frontman.Wrapper.NewIpset(name, ipsetType)
	if err != nil {
		return nil, err
	}
	return &winIPSet{ipsetHandle, name}, nil
}

// GetIpset gets the ipset object from the name.
// Note that the interface can't return error here, but since it's possible to fail in Windows,
// we log error and return incomplete object, and expect a failure from Frontman on a later call.
func (i *ipsetProvider) GetIpset(name string) Ipset {
	ipsetHandle, err := frontman.Wrapper.GetIpset(name)
	if err != nil {
		zap.L().Error(fmt.Sprintf("failed to get ipset %s", name), zap.Error(err))
		return &winIPSet{0, name}
	}
	return &winIPSet{ipsetHandle, name}
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *ipsetProvider) DestroyAll(prefix string) error {
	return frontman.Wrapper.DestroyAllIpsets(prefix)
}

func (i *ipsetProvider) ListIPSets() ([]string, error) {
	return frontman.Wrapper.ListIpsets()
}

// IPsetProvider Returns a Go IPSet Provider
func IPsetProvider() IpsetProvider {
	return instance
}

func (w *winIPSet) Add(entry string, timeout int) error {
	return frontman.Wrapper.IpsetAdd(w.handle, entry, timeout)
}

func (w *winIPSet) AddOption(entry string, option string, timeout int) error {
	return frontman.Wrapper.IpsetAddOption(w.handle, entry, option, timeout)
}

func (w *winIPSet) Del(entry string) error {
	return frontman.Wrapper.IpsetDelete(w.handle, entry)
}

func (w *winIPSet) Destroy() error {
	return frontman.Wrapper.IpsetDestroy(w.handle, w.name)
}

func (w *winIPSet) Flush() error {
	return frontman.Wrapper.IpsetFlush(w.handle)
}

func (w *winIPSet) Test(entry string) (bool, error) {
	return frontman.Wrapper.IpsetTest(w.handle, entry)
}

func newIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error) {
	return IPsetProvider().NewIpset(name, ipsetType, p)
}

func getIpset(name string) Ipset {
	return IPsetProvider().GetIpset(name)
}

func destroyAll(prefix string) error {
	return IPsetProvider().DestroyAll(prefix)
}

func listIPSets() ([]string, error) {
	return IPsetProvider().ListIPSets()
}

//SetIpsetTestInstance sets the test instance for ipsets
func SetIpsetTestInstance(ipsetprovider IpsetProvider) {
	instance = ipsetprovider
}

//SetIPsetPath is a no-op for windows
func SetIPsetPath() {
}
