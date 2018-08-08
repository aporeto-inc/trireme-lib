// +build windows darwin

package provider

import "github.com/bvandewalle/go-ipset/ipset"

type goIpsetProvider struct{}

type winipset struct{}

// NewIpset returns an IpsetProvider interface based on the go-ipset
// external package.
func (i *goIpsetProvider) NewIpset(name string, hasht string, p *ipset.Params) (Ipset, error) {
	return &winipset{}, nil
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *goIpsetProvider) DestroyAll() error {
	return ipset.DestroyAll()
}

// NewGoIPsetProvider Return a Go IPSet Provider
func NewGoIPsetProvider() IpsetProvider {
	return &goIpsetProvider{}
}

// Add
func (i *winipset) Add(entry string, timeout int) error {
	return nil
}

// AddOption
func (i *winipset) AddOption(entry string, option string, timeout int) error {
	return nil
}

// Del
func (i *winipset) Del(entry string) error {
	return nil
}

// Destroy
func (i *winipset) Destroy() error {
	return nil
}

// Flush
func (i *winipset) Flush() error {
	return nil
}

// Test
func (i *winipset) Test(entry string) (bool, error) {
	return true, nil
}
