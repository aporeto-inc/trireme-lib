// +build windows

package provider

import (
	"fmt"

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

type goIpsetProvider struct{}

// NewIpset returns an IpsetProvider interface based on the go-ipset
// external package.
func (i *goIpsetProvider) NewIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error) {
	return nil, fmt.Errorf("Not Supported on non linux platforms")
}

// GetIpset gets the ipset object from the name.
func (i *goIpsetProvider) GetIpset(name string) Ipset {
	return nil
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *goIpsetProvider) DestroyAll(prefix string) error {
	return nil
}

func (i *goIpsetProvider) ListIPSets() ([]string, error) {
	return []string{}, nil
}

// NewGoIPsetProvider Return a Go IPSet Provider
func NewGoIPsetProvider() IpsetProvider {
	return &goIpsetProvider{}
}
