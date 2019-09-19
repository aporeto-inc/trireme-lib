package ipsetmanager

import (
	"encoding/base64"
	"io"
	"net"

	"github.com/spaolacci/murmur3"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

func hashServiceID(serviceID string) string {
	hash := murmur3.New64()
	if _, err := io.WriteString(hash, serviceID); err != nil {
		return ""
	}

	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

func addToIPset(set provider.Ipset, data string) error {

	// ipset can not program this rule
	if data == IPv4DefaultIP {
		if err := addToIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		return addToIPset(set, "128.0.0.0/1")
	}

	// ipset can not program this rule
	if data == IPv6DefaultIP {
		if err := addToIPset(set, "::/1"); err != nil {
			return err
		}

		return addToIPset(set, "8000::/1")
	}

	return set.Add(data, 0)
}

func delFromIPset(set provider.Ipset, data string) error {

	if data == IPv4DefaultIP {
		if err := delFromIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		return delFromIPset(set, "128.0.0.0/1")
	}

	if data == IPv6DefaultIP {
		if err := delFromIPset(set, "::/1"); err != nil {
			return err
		}

		return delFromIPset(set, "8000::/1")
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

type ExternalNetIPs struct {
	serviceID string
	addresses []string
}

type ipsetInfo struct {
	refCount int
	ipset    string
	ips      map[string]bool
}

type ipsetManager struct {
	serviceIDtoIpset      map[string]*ipsetInfo
	contextIDtoServiceIDs map[string]map[string]bool
	ipset                 provider.IpsetProvider
}

var ipsetManager = ipsetManager{}

func init() {
	ipsetManager.serviceIDtoIpset = map[string]*ipsetInfo{}
	ipsetManager.contextIDtoServiceIDs = map[string]map[string]bool{}
	ipsetManager.ips = provider.NewGoIPsetProvider()
}

func synchronizeIPsinIpset(ipsetInfo *ipsetInfo, addresses []string, ipFilter func(net.IP) bool) {
	newips := map[string]bool{}
	ipsetHandler := ipsetManager.ips.GetIpset(ipsetInfo.ipset)

	for _, address := range rule.Addresses {
		netIP := net.ParseIP(address)
		if netIP == nil {
			netIP, _, _ = net.ParseCIDR(address)
		}

		if !ipFilter(netIP) {
			continue
		}

		newips[address] = true
		if ipsetInfo.ips[address] == true {
			delete(ipsetInfo.ips, address)
		} else {
			if err := addToIPset(ipsetHandler, address); err != nil {
				return nil, err
			}
		}
	}

	// Remove the old entries
	for address, val := range ipsetInfo.ips {
		if val {
			if err := delFromIPset(ipsetHandler, address); err != nil {
				return nil, err
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
			ips := i.ipset.GetIpset(ipsetInfo.ipset)
			if err := ips.Destroy(); err != nil {
				zap.L().Warn("Failed to destroy ipset " + info.ipset)
			}
		}
	}
}

func GetACLIPSets(contextID string, appExtnets policy.IPRuleList, netExtnets policy.IPRuleList, ipFilter func(net.IP) bool, ipsetPrefix string, ipsetParams *ipset.Params) ([]string, []string, error) {
	var info *ipsetInfo
	var newServiceIDs map[string]bool

	for _, extnet := range extnets {
		var ipsetInfo *ipsetInfo
		if ipsets.serviceIDToIpset[extnet.serviceID] == nil {
			ipsetName := "extnet-" + ipsetPrefix + hashServiceID(rule.Policy.ServiceID)
			set, err := i.ipset.NewIpset(ipsetName, "hash:net", ipsetParams)
			if err != nil {
				return nil, err
			}

			ipsetinfo = &ipsetInfo{ipset: ipsetName, ips: map[string]bool{}}
			ipsets.serviceIDToIpset[extnet.serviceID] = ipsetInfo
		} else {
			ipsetInfo = ipsets.serviceIDToIpset[extnet.serviceID]
		}

		synchronizeIPsinIpset(ipsetInfo, extnet.addresses, ipFilter)

		ipsetInfo.refCount++
		newServiceIDs[extnet.serviceID] = true
		delete(ipsets.contextIDtoServiceIDs[contextID], extnet.serviceID)
	}

	// decrement refcount
	decRefCountForServiceIDs(ipsetManager.contextIDtoServiceIDs[contextID])
	ipsetManager.contextIDtoServiceIDs[contextID] = newServiceIDs
}

func RemoveContextIDFromExtNets(contextID string) {
	decRefCountForServiceIDs(ipsetManager.contextIDtoServiceIDs[contextID])
}
