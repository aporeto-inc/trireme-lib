// +build windows

package provider

import (
	"fmt"

	"github.com/bvandewalle/go-ipset/ipset"
)

type goIpsetProvider struct{}

type Ipset struct{}

// NewIpset returns an IpsetProvider interface based on the go-ipset
// external package.
func (i *goIpsetProvider) NewIpset(name string, hasht string, p *ipset.Params) (Ipset, error) {
	return nil, fmt.Errorf("Not Supported on non linux platforms")
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *goIpsetProvider) DestroyAll() error {
	return nil
}

// NewGoIPsetProvider Return a Go IPSet Provider
func NewGoIPsetProvider() IpsetProvider {
	return &goIpsetProvider{}
}
