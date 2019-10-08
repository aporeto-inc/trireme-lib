package ipsetmanager

import (
	"encoding/base64"
	"io"
	"net"
	"sync"

	ipsetpackage "github.com/aporeto-inc/go-ipset/ipset"
	"github.com/spaolacci/murmur3"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"

	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

const (
	//IPv6DefaultIP is the default ip of v6
	IPv6DefaultIP = "::/0"
	//IPv4DefaultIP is the  default ip for v4
	IPv4DefaultIP = "0.0.0.0/0"
	//IPsetV4 version for ipv4
	IPsetV4 = iota
	//IPsetV6 version for ipv6
	IPsetV6
)

//ACLManager interface is used by supervisor. This interface provides the supervisor to
//create ipsets corresponding to service ID.
type ACLManager interface {
	AddToIPset(set provider.Ipset, data string) error
	DelFromIPset(set provider.Ipset, data string) error

	RegisterExternalNets(contextID string, extnets policy.IPRuleList) error
	DestroyUnusedIPsets()
	RemoveExternalNets(contextID string)
	GetIPsets(extnets policy.IPRuleList, ipver int) []string
	UpdateIPsets([]string, string)
}

type ipsetInfo struct {
	contextIDs map[string]bool
	name       string
	addresses  map[string]bool
}

type handler struct {
	serviceIDtoIPset      map[string]*ipsetInfo
	contextIDtoServiceIDs map[string]map[string]bool
	ipset                 provider.IpsetProvider
	ipsetPrefix           string
	ipFilter              func(net.IP) bool
	ipsetParams           *ipsetpackage.Params
	toDestroy             []string
}

type managerType struct {
	ipv4Handler *handler
	ipv6Handler *handler
	sync.RWMutex
}

const (
	ipv4String = "v4-"
	ipv6String = "v6-"
)

//CreateIPsetManager creates the handle with Interface ACLManager
func CreateIPsetManager(ipsetv4 provider.IpsetProvider, ipsetv6 provider.IpsetProvider) ACLManager {
	return &managerType{
		ipv4Handler: &handler{
			serviceIDtoIPset:      map[string]*ipsetInfo{},
			contextIDtoServiceIDs: map[string]map[string]bool{},
			ipset:                 ipsetv4,
			ipsetPrefix:           ipv4String,
			ipFilter: func(ip net.IP) bool {
				return (ip.To4() != nil)
			},
			ipsetParams: &ipsetpackage.Params{},
		},
		ipv6Handler: &handler{
			serviceIDtoIPset:      map[string]*ipsetInfo{},
			contextIDtoServiceIDs: map[string]map[string]bool{},
			ipset:                 ipsetv6,
			ipsetPrefix:           ipv6String,
			ipFilter: func(ip net.IP) bool {
				return (ip.To4() == nil)
			},
			ipsetParams: &ipsetpackage.Params{HashFamily: "inet6"},
		},
	}

}

func hashServiceID(serviceID string) string {
	hash := murmur3.New64()
	if _, err := io.WriteString(hash, serviceID); err != nil {
		return ""
	}

	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// AddToIPset is called with the ipset provider and the ip address to be added
func (m *managerType) AddToIPset(set provider.Ipset, data string) error {

	// ipset can not program this rule
	if data == IPv4DefaultIP {
		if err := m.AddToIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		return m.AddToIPset(set, "128.0.0.0/1")
	}

	// ipset can not program this rule
	if data == IPv6DefaultIP {
		if err := m.AddToIPset(set, "::/1"); err != nil {
			return err
		}

		return m.AddToIPset(set, "8000::/1")
	}

	return set.Add(data, 0)
}

// DelFromIPset is called with the ipset set provider and the ip to be removed from ipset
func (m *managerType) DelFromIPset(set provider.Ipset, data string) error {

	if data == IPv4DefaultIP {
		if err := m.DelFromIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		return m.DelFromIPset(set, "128.0.0.0/1")
	}

	if data == IPv6DefaultIP {
		if err := m.DelFromIPset(set, "::/1"); err != nil {
			return err
		}

		return m.DelFromIPset(set, "8000::/1")
	}

	return set.Del(data)
}

func (m *managerType) synchronizeIPsinIpset(ipHandler *handler, ipsetInfo *ipsetInfo, addresses []string) {
	newips := map[string]bool{}
	ipsetHandler := ipHandler.ipset.GetIpset(ipsetInfo.name)

	for _, address := range addresses {
		netIP := net.ParseIP(address)
		if netIP == nil {
			netIP, _, _ = net.ParseCIDR(address)
		}

		if !ipHandler.ipFilter(netIP) {
			continue
		}

		newips[address] = true

		if _, ok := ipsetInfo.addresses[address]; !ok {
			if err := m.AddToIPset(ipsetHandler, address); err != nil {
				zap.L().Error("Error adding IPs to ipset", zap.String("ipset", ipsetInfo.name), zap.String("address", address))
			}
		}
		delete(ipsetInfo.addresses, address)
	}

	// Remove the old entries
	for address, val := range ipsetInfo.addresses {
		if val {
			if err := m.DelFromIPset(ipsetHandler, address); err != nil {
				zap.L().Error("Error removing IPs from ipset", zap.String("ipset", ipsetInfo.name), zap.String("address", address))
			}
		}
	}

	ipsetInfo.addresses = newips
}

func createIPset(ipHandler *handler, serviceID string) (*ipsetInfo, error) {
	ipsetName := "TRI-" + ipHandler.ipsetPrefix + "ext-" + hashServiceID(serviceID)
	_, err := ipHandler.ipset.NewIpset(ipsetName, "hash:net", ipHandler.ipsetParams)
	if err != nil {
		return nil, err
	}

	ipset := &ipsetInfo{contextIDs: map[string]bool{}, name: ipsetName, addresses: map[string]bool{}}
	ipHandler.serviceIDtoIPset[serviceID] = ipset

	return ipset, nil
}

func deleteServiceID(ipHandler *handler, serviceID string) {
	ipsetInfo := ipHandler.serviceIDtoIPset[serviceID]
	ipHandler.toDestroy = append(ipHandler.toDestroy, ipsetInfo.name)
	delete(ipHandler.serviceIDtoIPset, serviceID)
}

func reduceReferenceFromServiceID(ipHandler *handler, contextID string, serviceID string) {
	var ipset *ipsetInfo

	if ipset = ipHandler.serviceIDtoIPset[serviceID]; ipset == nil {
		zap.L().Error("Could not find ipset corresponding to serviceID", zap.String("serviceID", serviceID))
		return
	}

	delete(ipset.contextIDs, contextID)

	// there are no references from any pu. safe to destroy now
	if len(ipset.contextIDs) == 0 {
		deleteServiceID(ipHandler, serviceID)
	}
}

// RegisterExternalNets registers the contextID and the corresponding serviceIDs
func (m *managerType) RegisterExternalNets(contextID string, extnets policy.IPRuleList) error {
	m.Lock()
	defer m.Unlock()

	processExtnets := func(ipHandler *handler) error {
		for _, extnet := range extnets {
			var ipset *ipsetInfo

			serviceID := extnet.Policy.ServiceID
			if ipset = ipHandler.serviceIDtoIPset[serviceID]; ipset == nil {
				var err error
				if ipset, err = createIPset(ipHandler, serviceID); err != nil {
					return err
				}
			}

			m.synchronizeIPsinIpset(ipHandler, ipset, extnet.Addresses)
			// have a backreference from serviceID to contextID
			ipset.contextIDs[contextID] = true
		}

		return nil
	}

	processOlderExtnets := func(ipHandler *handler) {
		newExtnets := map[string]bool{}

		for _, extnet := range extnets {

			serviceID := extnet.Policy.ServiceID
			newExtnets[serviceID] = true
			m, ok := ipHandler.contextIDtoServiceIDs[contextID]

			if ok && m[serviceID] {
				delete(m, serviceID)
			}
		}

		for serviceID := range ipHandler.contextIDtoServiceIDs[contextID] {
			reduceReferenceFromServiceID(ipHandler, contextID, serviceID)
		}

		ipHandler.contextIDtoServiceIDs[contextID] = newExtnets
	}

	if err := processExtnets(m.ipv4Handler); err != nil {
		return err
	}

	if err := processExtnets(m.ipv6Handler); err != nil {
		return err
	}

	processOlderExtnets(m.ipv4Handler)
	processOlderExtnets(m.ipv6Handler)

	return nil
}

// DestroyUnusedIPsets destroys the unused ipsets.
func (m *managerType) DestroyUnusedIPsets() {
	m.Lock()
	defer m.Unlock()

	destroy := func(ipHandler *handler) {
		for _, ipsetName := range ipHandler.toDestroy {
			ipsetHandler := ipHandler.ipset.GetIpset(ipsetName)
			if err := ipsetHandler.Destroy(); err != nil {
				zap.L().Warn("Failed to destroy ipset", zap.String("ipset", ipsetName), zap.Error(err))
			}

		}
	}

	destroy(m.ipv4Handler)
	destroy(m.ipv6Handler)
}

// RemoveExternalNets is called when the contextID is being unsupervised such that all the external nets can be deleted.
func (m *managerType) RemoveExternalNets(contextID string) {
	m.Lock()

	process := func(ipHandler *handler) {
		m, ok := ipHandler.contextIDtoServiceIDs[contextID]
		if ok {
			for serviceID := range m {
				reduceReferenceFromServiceID(ipHandler, contextID, serviceID)
			}
		}

		delete(ipHandler.contextIDtoServiceIDs, contextID)
	}

	process(m.ipv4Handler)
	process(m.ipv6Handler)

	m.Unlock()
	m.DestroyUnusedIPsets()
}

// GetIPsets returns the ipset names corresponding to the serviceIDs.
func (m *managerType) GetIPsets(extnets policy.IPRuleList, ipver int) []string {
	m.Lock()
	defer m.Unlock()

	var ipHandler *handler

	if ipver == IPsetV4 {
		ipHandler = m.ipv4Handler
	} else {
		ipHandler = m.ipv6Handler
	}

	var ipsets []string

	for _, extnet := range extnets {
		serviceID := extnet.Policy.ServiceID

		ipsetInfo, ok := ipHandler.serviceIDtoIPset[serviceID]
		if ok {
			ipsets = append(ipsets, ipsetInfo.name)
		}
	}

	return ipsets
}

// UpdateIPsets updates the ip addresses in the ipsets corresponding to the serviceID
func (m *managerType) UpdateIPsets(addresses []string, serviceID string) {
	m.Lock()
	defer m.Unlock()

	process := func(ipHandler *handler) {
		for _, address := range addresses {
			netIP := net.ParseIP(address)
			if netIP == nil {
				netIP, _, _ = net.ParseCIDR(address)
			}

			if !ipHandler.ipFilter(netIP) {
				continue
			}

			if ipset := ipHandler.serviceIDtoIPset[serviceID]; ipset != nil {
				ipsetHandler := ipHandler.ipset.GetIpset(ipset.name)
				if err := m.AddToIPset(ipsetHandler, address); err != nil {
					zap.L().Error("Error adding IPs to ipset", zap.String("ipset", ipset.name), zap.String("address", address))
				}
				ipset.addresses[address] = true
			}
		}
	}

	process(m.ipv4Handler)
	process(m.ipv6Handler)
}
