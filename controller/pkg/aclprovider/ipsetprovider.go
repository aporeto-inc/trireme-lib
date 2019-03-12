package provider

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/aporeto-inc/go-ipset/ipset"
)

// IpsetProvider returns a fabric for Ipset.
type IpsetProvider interface {
	NewIpset(name string, hasht string, p *ipset.Params) (Ipset, error)
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
func (i *goIpsetProvider) NewIpset(name string, hasht string, p *ipset.Params) (Ipset, error) {
	return ipset.New(name, hasht, p)
}

// GetIpset gets the ipset object from the name.
func (i *goIpsetProvider) GetIpset(name string) Ipset {
	return &ipset.IPSet{
		Name: name,
	}
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *goIpsetProvider) DestroyAll(prefix string) error {

	sets, err := i.ListIPSets()
	if err != nil {
		return ipset.DestroyAll()
	}

	for _, s := range sets {
		if !strings.HasPrefix(s, prefix) {
			continue
		}
		ips := i.GetIpset(s)
		if err := ips.Destroy(); err != nil {
			return ipset.DestroyAll()
		}
	}

	return nil
}

func (i *goIpsetProvider) ListIPSets() ([]string, error) {

	path, err := exec.LookPath("ipset")
	if err != nil {
		return nil, fmt.Errorf("ipset command not found: %s", err)
	}

	out, err := exec.Command(path, "-L", "-name").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("unable to list ipsets:%s", err)
	}

	return strings.Split(string(out), "\n"), nil
}

// NewGoIPsetProvider Return a Go IPSet Provider
func NewGoIPsetProvider() IpsetProvider {
	return &goIpsetProvider{}
}
