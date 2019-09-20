package ipsetmanager

import (
	"encoding/base64"
	"io"
	"net"

	"github.com/aporeto-inc/go-ipset/ipset"
	"github.com/spaolacci/murmur3"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"

	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

const (
	IPv6DefaultIP = "::/0"
	IPv4DefaultIP = "0.0.0.0/0"
)

type ExternalNetIPs struct {
	serviceID string
	addresses []string
}

type ipsetInfo struct {
	refCount int
	name     string
	ips      map[string]bool
}

type ipsetHandler struct {
	serviceIDtoIpset      map[string]*ipsetInfo
	contextIDtoServiceIDs map[string]map[string]bool
	ipset                 provider.IpsetProvider
}

var ipsetManager = ipsetHandler{}

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

// func (i *iptables) UpdateIPsets(ips []string, serviceID string) {
// 	var ipsetInfo *ipsetInfo

// 	ipFilter := i.impl.IPFilter()
// 	if ipsetInfo = i.serviceIDToIPsets[serviceID]; ipsetInfo == nil {
// 		return
// 	}

// 	for _, ip := range ips {
// 		var netIP net.IP
// 		if netIP = net.ParseIP(ip); netIP == nil {
// 			return
// 		}

// 		if !ipFilter(netIP) {
// 			continue
// 		}

// 		addToIPset(i.ipset.GetIpset(ipsetInfo.ipset), ip)
// 	}
// }

func init() {
	ipsetManager.serviceIDtoIpset = map[string]*ipsetInfo{}
	ipsetManager.contextIDtoServiceIDs = map[string]map[string]bool{}
	ipsetManager.ipset = provider.NewGoIPsetProvider()
}

func synchronizeIPsinIpset(ipsetInfo *ipsetInfo, addresses []string, ipFilter func(net.IP) bool) {
	newips := map[string]bool{}
	ipsetHandler := ipsetManager.ipset.GetIpset(ipsetInfo.name)

	for _, address := range addresses {
		netIP := net.ParseIP(address)
		if netIP == nil {
			netIP, _, _ = net.ParseCIDR(address)
		}

		if !ipFilter(netIP) {
			continue
		}

		newips[address] = true

		_, ok := ipsetInfo.ips[address]
		if ok {
			delete(ipsetInfo.ips, address)
		} else {
			if err := AddToIPset(ipsetHandler, address); err != nil {
				zap.L().Error("Error adding IPs to ipset", zap.String("ipset", ipsetInfo.name), zap.String("address", address))
			}
		}
	}

	// Remove the old entries
	for address, val := range ipsetInfo.ips {
		if val {
			if err := DelFromIPset(ipsetHandler, address); err != nil {
				zap.L().Error("Error removing IPs from ipset", zap.String("ipset", ipsetInfo.name), zap.String("address", address))
			}
		}
	}

	ipsetInfo.ips = newips
}

func decRefCountForServiceIDs(serviceIDMap map[string]bool) {
	for serviceID, _ := range serviceIDMap {
		ipsetInfo := ipsetManager.serviceIDtoIpset[serviceID]
		ipsetInfo.refCount--
		if ipsetInfo.refCount == 0 {
			// destroy ipsets as there is no reference
			ips := ipsetManager.ipset.GetIpset(ipsetInfo.name)
			if err := ips.Destroy(); err != nil {
				zap.L().Warn("Failed to destroy ipset " + ipsetInfo.name)
			}

			delete(ipsetManager.serviceIDtoIpset, serviceID)
		}
	}
}

func GetACLIPSets(contextID string, appExtnets policy.IPRuleList, netExtnets policy.IPRuleList, ipFilter func(net.IP) bool, ipsetPrefix string, ipsetParams *ipset.Params) ([]string, []string, error) {
	newServiceIDs := map[string]bool{}

	contextID = contextID + ipsetPrefix

	process := func(extnets policy.IPRuleList) ([]string, error) {
		var ipsets []string
		for _, extnet := range extnets {
			var ipset *ipsetInfo
			serviceID := extnet.Policy.ServiceID + ipsetPrefix
			if ipsetManager.serviceIDtoIpset[serviceID] == nil {
				ipsetName := "extnet-" + ipsetPrefix + hashServiceID(serviceID)
				_, err := ipsetManager.ipset.NewIpset(ipsetName, "hash:net", ipsetParams)
				if err != nil {
					return nil, err
				}

				ipset = &ipsetInfo{name: ipsetName, ips: map[string]bool{}}
				ipsetManager.serviceIDtoIpset[serviceID] = ipset
			} else {
				ipset = ipsetManager.serviceIDtoIpset[serviceID]
			}

			ipsets = append(ipsets, ipset.name)
			synchronizeIPsinIpset(ipset, extnet.Addresses, ipFilter)

			ipset.refCount++
			newServiceIDs[serviceID] = true
			delete(ipsetManager.contextIDtoServiceIDs[contextID], serviceID)
		}
		return ipsets, nil
	}

	var appIPsets, netIPsets []string
	var err error

	if appIPsets, err = process(appExtnets); err != nil {
		return nil, nil, err
	}

	if netIPsets, err = process(netExtnets); err != nil {
		return nil, nil, err
	}
	// decrement refcount
	decRefCountForServiceIDs(ipsetManager.contextIDtoServiceIDs[contextID])
	ipsetManager.contextIDtoServiceIDs[contextID] = newServiceIDs

	return appIPsets, netIPsets, nil
}

func RemoveContextIDFromExtNets(contextID string, ipsetPrefix string) {
	contextID = contextID + ipsetPrefix
	decRefCountForServiceIDs(ipsetManager.contextIDtoServiceIDs[contextID])

	delete(ipsetManager.contextIDtoServiceIDs, contextID)
}
