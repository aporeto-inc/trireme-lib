// +build windows

package provider

import (
	"github.com/aporeto-inc/go-ipset/ipset"
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

type winIpSet struct{}

// NewIpset returns an IpsetProvider interface based on the go-ipset
// external package.
func (i *ipsetProvider) NewIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error) {
	return &winIpSet{}, nil
}

// GetIpset gets the ipset object from the name.
func (i *ipsetProvider) GetIpset(name string) Ipset {
	return &winIpSet{}
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *ipsetProvider) DestroyAll(prefix string) error {
	return nil
}

func (i *ipsetProvider) ListIPSets() ([]string, error) {
	return []string{}, nil
}

// NewGoIPsetProvider Return a Go IPSet Provider
func NewGoIPsetProvider() IpsetProvider {
	return &ipsetProvider{}
}

func (w *winIpSet) Add(entry string, timeout int) error {
	return nil
}

func (w *winIpSet) AddOption(entry string, option string, timeout int) error {
	return nil
}

func (w *winIpSet) Del(entry string) error {
	return nil
}

func (w *winIpSet) Destroy() error {
	return nil
}

func (w *winIpSet) Flush() error {
	return nil
}

func (w *winIpSet) Test(entry string) (bool, error) {
	return false, nil
}
