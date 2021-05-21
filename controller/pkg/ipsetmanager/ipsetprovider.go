// +build linux darwin

package ipsetmanager

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.uber.org/zap"
)

var (
	// path to aporeto-ipset
	ipsetBinPath string
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

var instance IpsetProvider = &goIpsetProvider{}

func ipsetCreateBitmapPort(setname string) error {
	//Bitmap type is not supported by the ipset library
	out, err := exec.Command(ipsetBinPath, "create", setname, "bitmap:port", "range", "0-65535", "timeout", "0").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "set with the same name already exists") {
			zap.L().Warn("Set already exists - cleaning up", zap.String("set name", setname))
			// Clean up the existing set
			if _, cerr := exec.Command(ipsetBinPath, "-F", setname).CombinedOutput(); cerr != nil {
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

// DestroyAll destroys all the ipsets with the given prefix
func (i *goIpsetProvider) DestroyAll(prefix string) error {
	return ipset.DestroyAll(prefix)
}

func (i *goIpsetProvider) ListIPSets() ([]string, error) {

	out, err := exec.Command(ipsetBinPath, "-L", "-name").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("unable to list ipsets:%s", err)
	}

	return strings.Split(string(out), "\n"), nil
}

func newIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error) {
	return instance.NewIpset(name, ipsetType, p)
}

func getIpset(name string) Ipset {
	return instance.GetIpset(name)
}

func destroyAll(prefix string) error {
	return instance.DestroyAll(prefix)
}

func listIPSets() ([]string, error) {
	return instance.ListIPSets()
}

//SetIpsetTestInstance sets a test instance of ipsetprovider
func SetIpsetTestInstance(ipsetprovider IpsetProvider) {
	instance = ipsetprovider
}

//SetIPsetPath sets the path for aporeto-ipset
func SetIPsetPath() {
	ipsetBinPath, _ = exec.LookPath(constants.IpsetBinaryName) // nolint: errcheck
	// tell the go-ipset package which ipset binary to use
	ipset.Init(ipsetBinPath) // nolint: errcheck
}
