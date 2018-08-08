// +build windows darwin

package provider

type goIpsetProvider struct{}

type ipset struct{}

// NewIpset returns an IpsetProvider interface based on the go-ipset
// external package.
func (i *goIpsetProvider) NewIpset(name string, hasht string, p *ipset.Params) (Ipset, error) {
	return &ipset{}
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
func (i *ipset) Add(entry string, timeout int) error {
	return nil
}

// AddOption
func (i *ipset) AddOption(entry string, option string, timeout int) error {
	return nil
}

// Del
func (i *ipset) Del(entry string) error {
	return nil
}

// Destroy
func (i *ipset) Destroy() error {
	return nil
}

// Flush
func (i *ipset) Flush() error {
	return nil
}

// Test
func (i *ipset) Test(entry string) (bool, error) {
	return true, nil
}
