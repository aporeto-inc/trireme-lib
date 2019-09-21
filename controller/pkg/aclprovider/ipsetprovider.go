package provider

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.uber.org/zap"
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

func ipsetCreateBitmapPort(setname string) error {
	//Bitmap type is not supported by the ipset library
	path, _ := exec.LookPath("ipset")
	out, err := exec.Command(path, "create", setname, "bitmap:port", "range", "0-65535", "timeout", "0").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "set with the same name already exists") {
			zap.L().Warn("Set already exists - cleaning up", zap.String("set name", setname))
			// Clean up the existing set
			if _, cerr := exec.Command(path, "-F", setname).CombinedOutput(); cerr != nil {
				return fmt.Errorf("Failed to clean up existing ipset: %s", err)
			}
			return nil
		}
		zap.L().Error("Unable to create set", zap.String("set name", setname), zap.String("ipset-output", string(out)))
	}
	return err
}

// NewIpset returns an IpsetProvider interface based on the go-ipset
// external package.
func (i *goIpsetProvider) NewIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error) {
	// Check if hashtype is a type of hash
	if strings.HasPrefix(ipsetType, "hash:") {
		return ipset.New(name, ipsetType, p)
	}

	if err := ipsetCreateBitmapPort(name); err != nil {
		return nil, err
	}

	return &ipset.IPSet{Name: name}, nil
}

// GetIpset gets the ipset object from the name.
func (i *goIpsetProvider) GetIpset(name string) Ipset {
	return &ipset.IPSet{
		Name: name,
	}
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *goIpsetProvider) DestroyAll(prefix string) error {

	return ipset.DestroyAll()
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
