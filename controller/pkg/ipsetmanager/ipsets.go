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
	///IPsetV6 version for ipv6
	IPsetV6
)

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

var lock sync.RWMutex
var ipv4Handler *handler
var ipv6Handler *handler

const (
	ipv4String = "v4-"
	ipv6String = "v6-"
)

// SetIpsetProvider sets the ipset providers for these handlers
func SetIpsetProvider(ipset provider.IpsetProvider, ipsetVersion int) {
	if ipsetVersion == IPsetV4 {
		ipv4Handler = &handler{
			serviceIDtoIPset:      map[string]*ipsetInfo{},
			contextIDtoServiceIDs: map[string]map[string]bool{},
			ipset:                 ipset,
			ipsetPrefix:           ipv4String,
			ipFilter: func(ip net.IP) bool {
				return (ip.To4() != nil)
			},
			ipsetParams: &ipsetpackage.Params{},
		}

	} else {
		ipv6Handler = &handler{
			serviceIDtoIPset:      map[string]*ipsetInfo{},
			contextIDtoServiceIDs: map[string]map[string]bool{},
			ipset:                 ipset,
			ipsetPrefix:           ipv6String,
			ipFilter: func(ip net.IP) bool {
				return (ip.To4() == nil)
			},
			ipsetParams: &ipsetpackage.Params{HashFamily: "inet6"},
		}
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
func AddToIPset(set provider.Ipset, data string) error {

	// ipset can not program this rule
	if data == IPv4DefaultIP {
		if err := AddToIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		return AddToIPset(set, "128.0.0.0/1")
	}

	// ipset can not program this rule
	if data == IPv6DefaultIP {
		if err := AddToIPset(set, "::/1"); err != nil {
			return err
		}

		return AddToIPset(set, "8000::/1")
	}

	return set.Add(data, 0)
}

// DelFromIPset is called with the ipset set provider and the ip to be removed from ipset
func DelFromIPset(set provider.Ipset, data string) error {

	if data == IPv4DefaultIP {
		if err := DelFromIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		return DelFromIPset(set, "128.0.0.0/1")
	}

	if data == IPv6DefaultIP {
		if err := DelFromIPset(set, "::/1"); err != nil {
			return err
		}

		return DelFromIPset(set, "8000::/1")
	}

	return set.Del(data)
}

func synchronizeIPsinIpset(ipHandler *handler, ipsetInfo *ipsetInfo, addresses []string) {
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
			if err := AddToIPset(ipsetHandler, address); err != nil {
				zap.L().Error("Error adding IPs to ipset", zap.String("ipset", ipsetInfo.name), zap.String("address", address))
			}
		}
		delete(ipsetInfo.addresses, address)
	}

	// Remove the old entries
	for address, val := range ipsetInfo.addresses {
		if val {
			if err := DelFromIPset(ipsetHandler, address); err != nil {
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
func RegisterExternalNets(contextID string, extnets policy.IPRuleList) error {
	lock.Lock()
	defer lock.Unlock()

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

			synchronizeIPsinIpset(ipHandler, ipset, extnet.Addresses)
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

	if err := processExtnets(ipv4Handler); err != nil {
		return err
	}

	if err := processExtnets(ipv6Handler); err != nil {
		return err
	}

	processOlderExtnets(ipv4Handler)
	processOlderExtnets(ipv6Handler)

	return nil
}

// DestroyUnusedIPsets destroys the unused ipsets.
func DestroyUnusedIPsets() {
	lock.Lock()
	defer lock.Unlock()

	destroy := func(ipHandler *handler) {
		for _, ipsetName := range ipHandler.toDestroy {
			ipsetHandler := ipHandler.ipset.GetIpset(ipsetName)
			if err := ipsetHandler.Destroy(); err != nil {
				zap.L().Warn("Failed to destroy ipset", zap.String("ipset", ipsetName), zap.Error(err))
			}

		}
	}

	destroy(ipv4Handler)
	destroy(ipv6Handler)
}

// RemoveExternalNets is called when the contextID is being unsupervised such that all the external nets can be deleted.
func RemoveExternalNets(contextID string) {
	lock.Lock()

	process := func(ipHandler *handler) {
		m, ok := ipHandler.contextIDtoServiceIDs[contextID]
		if ok {
			for serviceID := range m {
				reduceReferenceFromServiceID(ipHandler, contextID, serviceID)
			}
		}

		delete(ipHandler.contextIDtoServiceIDs, contextID)
	}

	process(ipv4Handler)
	process(ipv6Handler)

	lock.Unlock()
	DestroyUnusedIPsets()
}

// GetIPsets returns the ipset names corresponding to the serviceIDs.
func GetIPsets(extnets policy.IPRuleList, ipver int) []string {
	lock.Lock()
	defer lock.Unlock()

	var ipHandler *handler

	if ipver == IPsetV4 {
		ipHandler = ipv4Handler
	} else {
		ipHandler = ipv6Handler
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
func UpdateIPsets(addresses []string, serviceID string) {
	lock.Lock()
	defer lock.Unlock()

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
				if err := AddToIPset(ipsetHandler, address); err != nil {
					zap.L().Error("Error adding IPs to ipset", zap.String("ipset", ipset.name), zap.String("address", address))
				}
				ipset.addresses[address] = true
			}
		}
	}

	process(ipv4Handler)
	process(ipv6Handler)
}
