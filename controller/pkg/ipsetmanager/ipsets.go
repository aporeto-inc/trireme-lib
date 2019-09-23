package ipsetmanager

import (
	"encoding/base64"
	"io"
	"net"
	"sync"

	"github.com/aporeto-inc/go-ipset/ipset"
	"github.com/spaolacci/murmur3"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"

	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

const (
	IPv6DefaultIP = "::/0"
	IPv4DefaultIP = "0.0.0.0/0"
	IPsetV4       = iota
	IPsetV6
)

type ExternalNetIPs struct {
	serviceID string
	addresses []string
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
	ipsetParams           *ipset.Params
	toDestroy             []string
}

var lock sync.RWMutex
var ipv4Handler handler
var ipv6Handler handler

const (
	ipv4String = "v4-"
	ipv6String = "v6-"
)

func init() {
	ipv4Handler = handler{
		serviceIDtoIPset:      map[string]*ipsetInfo{},
		contextIDtoServiceIDs: map[string]map[string]bool{},
		ipsetPrefix:           ipv4String,
		ipFilter: func(ip net.IP) bool {
			return (ip.To4() != nil)
		},
		ipsetParams: &ipset.Params{},
	}

	ipv6Handler = handler{
		serviceIDtoIPset:      map[string]*ipsetInfo{},
		contextIDtoServiceIDs: map[string]map[string]bool{},
		ipsetPrefix:           ipv4String,
		ipFilter: func(ip net.IP) bool {
			return (ip.To4() == nil)
		},
		ipsetParams: &ipset.Params{HashFamily: "inet6"},
	}
}

func SetIpsetProvider(ipset provider.IpsetProvider, ipsetVersion int) {
	if ipsetVersion == IPsetV4 {
		ipv4Handler.ipset = ipset
	} else {
		ipv6Handler.ipset = ipset
	}
}

func hashServiceID(serviceID string) string {
	hash := murmur3.New64()
	if _, err := io.WriteString(hash, serviceID); err != nil {
		return ""
	}

	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

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

		if _, ok := ipsetInfo.addresses[address]; ok {
			delete(ipsetInfo.addresses, address)
		} else {
			if err := AddToIPset(ipsetHandler, address); err != nil {
				zap.L().Error("Error adding IPs to ipset", zap.String("ipset", ipsetInfo.name), zap.String("address", address))
			}
		}
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

func RegisterExternalNets(contextID string, extnets policy.IPRuleList) {

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

		for serviceID, _ := range ipHandler.contextIDtoServiceIDs[contextID] {
			reduceReferenceFromServiceID(ipHandler, contextID, serviceID)
		}

		ipHandler.contextIDtoServiceIDs[contextID] = newExtnets
	}

	if err := processExtnets(&ipv4Handler); err != nil {
	}

	if err := processExtnets(&ipv6Handler); err != nil {
	}

	processOlderExtnets(&ipv4Handler)
	processOlderExtnets(&ipv6Handler)
}

func DestroyUnusedIPsets() {
	destroy := func(ipHandler *handler) {
		for _, ipsetName := range ipHandler.toDestroy {
			ipsetHandler := ipHandler.ipset.GetIpset(ipsetName)
			if err := ipsetHandler.Destroy(); err != nil {
				zap.L().Warn("Failed to destroy ipset", zap.String("ipset", ipsetName), zap.Error(err))
			}

		}
	}

	destroy(&ipv4Handler)
	destroy(&ipv6Handler)
}

func RemoveExternalNets(contextID string) {
	process := func(ipHandler *handler) {
		m, ok := ipHandler.contextIDtoServiceIDs[contextID]
		if ok {
			for serviceID, _ := range m {
				reduceReferenceFromServiceID(ipHandler, contextID, serviceID)
			}
		}

		delete(ipHandler.contextIDtoServiceIDs, contextID)
	}

	process(&ipv4Handler)
	process(&ipv6Handler)

	DestroyUnusedIPsets()
}

func GetIPsets(extnets policy.IPRuleList, ipver int) []string {
	var ipHandler *handler

	if ipver == IPsetV4 {
		ipHandler = &ipv4Handler
	} else {
		ipHandler = &ipv6Handler
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

	process(&ipv4Handler)
	process(&ipv6Handler)
}
