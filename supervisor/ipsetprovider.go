package supervisor

import "github.com/janeczku/go-ipset/ipset"

// IpsetProvider is an abstraction of all the methods an implementation of userspace
// ipsets need to provide.
type IpsetProvider interface {
	Add(entry string, timeout int) error
	Del(entry string) error
	Destroy() error
	Flush() error
	Test(entry string) (bool, error)
}

// NewIPset returns an IpsetProvider interface based on the go-iptables
// external package.
func NewIPset(name string, hasht string, p *ipset.Params) (IpsetProvider, error) {
	return ipset.New(name, hasht, p)
}
