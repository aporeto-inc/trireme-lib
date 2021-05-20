package ipsetmanager

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	ipsetpackage "github.com/aporeto-inc/go-ipset/ipset"
	"github.com/spaolacci/murmur3"

	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
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

	processPortSetPrefix = "ProcPort-"
	proxyPortSetPrefix   = "Proxy-"
	targetTCPSuffix      = "TargetTCP"
	targetUDPSuffix      = "TargetUDP"
	excludedSuffix       = "Excluded"
)

//TargetAndExcludedNetworks interface is used to interact with target and excluded networks
type TargetAndExcludedNetworks interface {
	//CreateIPsetsForTargetAndExcludedNetworks creates the ipsets for target and excluded networks
	CreateIPsetsForTargetAndExcludedNetworks() error
	//UpdateIPsetsForTargetAndExcludedNetworks updates the ipsets accordingly.
	UpdateIPsetsForTargetAndExcludedNetworks([]string, []string, []string) error
	//GetIPsetNamesForTargetAndExcludedNetworks returns the ipsets names for tcp, udp and excluded networks
	GetIPsetNamesForTargetAndExcludedNetworks() (string, string, string)
}

//ServerL3 interface is used to interact with the ipsets required to program
//ports that the server(PU) listens on in L3 datapath.
type ServerL3 interface {
	//CreateServerPortSet creates the ipset.
	CreateServerPortSet(contextID string) error
	//GetServerPortSetName returns the name of the portset created
	GetServerPortSetName(contextID string) string
	//DestroyServerPortSet destroys the server port set.
	DestroyServerPortSet(contextID string) error
	//AddPortToServerPortSet adds port to the portset.
	AddPortToServerPortSet(contextID string, port string) error
	//DeletePortFromServerPortSet deletes the port from port set.
	DeletePortFromServerPortSet(contextID string, port string) error
}

// ACLL3 interface is used to interact with the ipsets required for
// application and network acl's in L3.
type ACLL3 interface {
	//RegisterExternalNets registers the ipsets corresponding the external networks.
	RegisterExternalNets(contextID string, extnets policy.IPRuleList) error
	//AddACLIPsets adds the IPs in the ipsets corresponding to the external network service ID.
	UpdateACLIPsets([]string, string)
	//DestroyUnusedIPsets will remove the unused ipsets.
	DestroyUnusedIPsets()
	//RemoveExternalNets removes the external networks corresponding to the PU contextID.
	RemoveExternalNets(contextID string)
	//GetACLIPsets returns the ipset string that correspond to the external networks in the argument
	GetACLIPsetsNames(extnets policy.IPRuleList) []string
	// DeleteEntryFromIPset delete an entry from an ipset
	DeleteEntryFromIPset(ips []string, serviceID string)
}

//ProxyL4 interface is used to interact with the ipsets required for
//L4/L7 Services. These include dependent services and exposed Services
type ProxyL4 interface {
	//CreateProxySets creates the ipsets to implement L4/L7 services
	CreateProxySets(contextID string) error
	//GetProxyIPsetNames returns the ipset strings that correspond to the pu
	GetProxySetNames(contextID string) (string, string)
	//DestroyProxySet destroys the ipsets being used for L4/L7 services
	DestroyProxySets(contextID string)
	//FlushProxySets flushes the proxy IPsets
	FlushProxySets(contextID string)
	//AddIPPortToDependentService adds ip port to the dependent service
	AddIPPortToDependentService(contextID string, ip *net.IPNet, port string) error
	//AddPortToExposedService adds the port that this service is exposing
	AddPortToExposedService(contextID string, port string) error
}

//DestroyAll destroys all the ipsets created.
type DestroyAll interface {
	//DestroyAllIPsets destroys the created ipsets.
	DestroyAllIPsets() error
}

//IPsetPrefix returns the prefix used to construct the ipset.
type IPsetPrefix interface {
	//GetIPsetPrefix returns the prefix.
	GetIPsetPrefix() string
}

//IPSetManager interface is used by supervisor. This interface provides the supervisor to
//create ipsets corresponding to service ID.
type IPSetManager interface {
	TargetAndExcludedNetworks
	ServerL3
	ACLL3
	ProxyL4
	DestroyAll
	IPsetPrefix

	Reset()
}

type ipsetInfo struct {
	contextIDs map[string]bool
	name       string
	addresses  map[string]bool
}

type aclHandler struct {
	serviceIDtoACLIPset   map[string]*ipsetInfo
	contextIDtoServiceIDs map[string]map[string]bool
	toDestroy             []string
}

type targetNetwork struct {
	tcp []string
	udp []string
}

type excludedNetwork struct {
	excluded []string
}

type handler struct {
	sync.RWMutex

	ipsetPrefix string
	ipFilter    func(net.IP) bool
	ipsetParams *ipsetpackage.Params

	acl aclHandler
	tn  targetNetwork
	en  excludedNetwork

	dynamicUpdates map[string][]string
}

const (
	ipv4String = "v4-"
	ipv6String = "v6-"
)

var ipv4Handler = &handler{
	ipsetPrefix: constants.ChainPrefix + ipv4String,
	ipFilter: func(ip net.IP) bool {
		return (ip.To4() != nil)
	},
	ipsetParams: &ipsetpackage.Params{},

	acl: aclHandler{
		serviceIDtoACLIPset:   map[string]*ipsetInfo{},
		contextIDtoServiceIDs: map[string]map[string]bool{},
	},
	tn:             targetNetwork{tcp: []string{}, udp: []string{}},
	en:             excludedNetwork{excluded: []string{}},
	dynamicUpdates: map[string][]string{},
}

var ipv6Handler = &handler{
	ipsetPrefix: constants.ChainPrefix + ipv6String,
	ipFilter: func(ip net.IP) bool {
		return (ip.To4() == nil)
	},
	ipsetParams: &ipsetpackage.Params{HashFamily: "inet6"},

	acl: aclHandler{
		serviceIDtoACLIPset:   map[string]*ipsetInfo{},
		contextIDtoServiceIDs: map[string]map[string]bool{},
	},
	tn:             targetNetwork{tcp: []string{}, udp: []string{}},
	en:             excludedNetwork{excluded: []string{}},
	dynamicUpdates: map[string][]string{},
}

//V4 returns the ipv4 instance of ipsetmanager
func V4() IPSetManager {
	return ipv4Handler
}

//V6 returns the ipv6 instance of ipsetmanager
func V6() IPSetManager {
	return ipv6Handler
}

func (ipHandler *handler) DestroyAllIPsets() error {

	if err := destroyAll(ipHandler.ipsetPrefix); err != nil {
		return err
	}

	return nil
}

func (ipHandler *handler) Reset() {
	ipHandler.Lock()

	ipHandler.acl = aclHandler{
		serviceIDtoACLIPset:   map[string]*ipsetInfo{},
		contextIDtoServiceIDs: map[string]map[string]bool{},
	}

	ipHandler.tn = targetNetwork{tcp: []string{}, udp: []string{}}
	ipHandler.en = excludedNetwork{excluded: []string{}}

	ipHandler.Unlock()
}

func (ipHandler *handler) CreateIPsetsForTargetAndExcludedNetworks() error {

	targetTCPName := ipHandler.ipsetPrefix + targetTCPSuffix
	targetUDPName := ipHandler.ipsetPrefix + targetUDPSuffix
	excludedName := ipHandler.ipsetPrefix + excludedSuffix

	existingSets, err := listIPSets()
	if err != nil {
		return fmt.Errorf("unable to read current sets: %s", err)
	}

	setIndex := map[string]struct{}{}
	for _, s := range existingSets {
		setIndex[s] = struct{}{}
	}

	createIPSet := func(name string) error {
		var ipset Ipset
		var err error

		if _, ok := setIndex[name]; !ok {
			ipset, err = newIpset(name, "hash:net", ipHandler.ipsetParams)
			if err != nil {
				return err
			}
		} else {
			ipset = getIpset(name)
		}

		if err = ipset.Flush(); err != nil {
			return err
		}

		return nil
	}

	if err := createIPSet(targetTCPName); err != nil {
		return err
	}

	if err := createIPSet(targetUDPName); err != nil {
		return err
	}

	if err := createIPSet(excludedName); err != nil {
		return err
	}

	return nil
}

func updateIPSets(ipset Ipset, old []string, new []string) error {
	// We need to delete first, because of nomatch.
	// For example, if old has 1.2.3.4 and new has !1.2.3.4, then we delete the 1.2.3.4 first
	// before we can add the 1.2.3.4 with the nomatch option.

	deleteMap := map[string]bool{}
	addMap := map[string]bool{}
	for _, net := range old {
		deleteMap[net] = true
	}
	for _, net := range new {
		if _, ok := deleteMap[net]; ok {
			deleteMap[net] = false
			continue
		}
		addMap[net] = true
	}

	for net, delete := range deleteMap {
		if delete {
			if err := delFromIPset(ipset, net); err != nil {
				zap.L().Debug("unable to remove network from set", zap.Error(err))
			}
		}
	}

	for net, add := range addMap {
		if add {
			if err := addToIPset(ipset, net); err != nil {
				return fmt.Errorf("unable to update target set: %s", err)
			}
		}
	}

	return nil
}

func (ipHandler *handler) UpdateIPsetsForTargetAndExcludedNetworks(tcp []string, udp []string, excluded []string) error {

	filterIPs := func(ips []string) []string {
		var filteredIPs []string

		for _, ip := range ips {
			parsable := ip
			if strings.HasPrefix(ip, "!") {
				parsable = ip[1:]
			}
			netIP := net.ParseIP(parsable)
			if netIP == nil {
				netIP, _, _ = net.ParseCIDR(parsable)
			}

			if ipHandler.ipFilter(netIP) {
				filteredIPs = append(filteredIPs, ip)
			}
		}

		return filteredIPs
	}

	tcpSet := getIpset(ipHandler.ipsetPrefix + targetTCPSuffix)
	udpSet := getIpset(ipHandler.ipsetPrefix + targetUDPSuffix)
	excludedSet := getIpset(ipHandler.ipsetPrefix + excludedSuffix)

	tcpFilterIPs := filterIPs(tcp)
	if err := updateIPSets(tcpSet, ipHandler.tn.tcp, tcpFilterIPs); err != nil {
		return err
	}

	udpFilterIPs := filterIPs(udp)
	if err := updateIPSets(udpSet, ipHandler.tn.udp, udpFilterIPs); err != nil {
		return err
	}

	excludedFilterIPs := filterIPs(excluded)
	if err := updateIPSets(excludedSet, ipHandler.en.excluded, excludedFilterIPs); err != nil {
		return err
	}

	ipHandler.tn.tcp = tcpFilterIPs
	ipHandler.tn.udp = udpFilterIPs
	ipHandler.en.excluded = excludedFilterIPs

	return nil
}

func (ipHandler *handler) GetIPsetNamesForTargetAndExcludedNetworks() (string, string, string) {
	return ipHandler.ipsetPrefix + targetTCPSuffix, ipHandler.ipsetPrefix + targetUDPSuffix, ipHandler.ipsetPrefix + excludedSuffix
}

func (ipHandler *handler) getServerPortSetName(contextID string) string {

	prefix := ipHandler.ipsetPrefix + processPortSetPrefix

	return createName(contextID, prefix)
}

func (ipHandler *handler) getProxyIPSetNames(contextID string) (string, string) {
	prefix := ipHandler.ipsetPrefix + proxyPortSetPrefix
	name := createName(contextID, prefix)

	return name + "-dst", name + "-srv"
}

func (ipHandler *handler) GetProxySetNames(contextID string) (string, string) {
	return ipHandler.getProxyIPSetNames(contextID)
}

func (ipHandler *handler) DestroyProxySets(contextID string) {
	destSetName, srvSetName := ipHandler.getProxyIPSetNames(contextID)

	ips := getIpset(destSetName)
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to destroy proxyPortSet", zap.String("SetName", destSetName), zap.Error(err))
	}

	ips = getIpset(srvSetName)
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to clear proxy port set", zap.String("set name", srvSetName), zap.Error(err))
	}
}

//CreateProxySets creates the ipsets for L4/L7 services
func (ipHandler *handler) CreateProxySets(contextID string) error {

	destSetName, srvSetName := ipHandler.getProxyIPSetNames(contextID)

	if _, err := newIpset(destSetName, "hash:net,port", ipHandler.ipsetParams); err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", destSetName, err)
	}

	// create ipset for port match
	if _, err := newIpset(srvSetName, proxySetPortIpsetType, nil); err != nil {
		return fmt.Errorf("unable to create ipset for %s: %s", srvSetName, err)
	}

	return nil
}

func (ipHandler *handler) FlushProxySets(contextID string) {
	destSetName, srvSetName := ipHandler.getProxyIPSetNames(contextID)

	ips := getIpset(destSetName)
	if err := ips.Flush(); err != nil {
		zap.L().Warn("Failed to flush dest proxy port set", zap.String("SetName", destSetName), zap.Error(err))
	}

	ips = getIpset(srvSetName)
	if err := ips.Flush(); err != nil {
		zap.L().Warn("Failed to flush server proxy port set", zap.String("set name", srvSetName), zap.Error(err))
	}
}

func (ipHandler *handler) AddIPPortToDependentService(contextID string, addr *net.IPNet, port string) error {

	destSetName, _ := ipHandler.getProxyIPSetNames(contextID)
	ips := getIpset(destSetName)

	if ipHandler.ipFilter(addr.IP) {
		pair := addr.String() + "," + port
		if err := ips.Add(pair, 0); err != nil {
			return fmt.Errorf("unable to add dependent ip %s to ipset: %s", pair, err)
		}
	}

	return nil
}

func (ipHandler *handler) AddPortToExposedService(contextID string, port string) error {
	_, srvSetName := ipHandler.getProxyIPSetNames(contextID)
	ips := getIpset(srvSetName)

	if err := ips.Add(port, 0); err != nil {
		return fmt.Errorf("unable to add port %s to exposed service %s", port, err)
	}

	return nil
}

func (ipHandler *handler) GetServerPortSetName(contextID string) string {
	return ipHandler.getServerPortSetName(contextID)
}

func (ipHandler *handler) CreateServerPortSet(contextID string) error {

	if _, err := newIpset(ipHandler.getServerPortSetName(contextID), portSetIpsetType, nil); err != nil {
		return err
	}

	return nil
}

func (ipHandler *handler) DestroyServerPortSet(contextID string) error {

	portSetName := ipHandler.getServerPortSetName(contextID)
	ips := getIpset(portSetName)

	if err := ips.Destroy(); err != nil {
		return fmt.Errorf("Failed to delete pu port set "+portSetName, zap.Error(err))
	}

	return nil
}

func (ipHandler *handler) AddPortToServerPortSet(contextID string, port string) error {

	ips := getIpset(ipHandler.getServerPortSetName(contextID))

	if err := ips.Add(port, 0); err != nil {
		return fmt.Errorf("unable to add port to portset: %s", err)
	}

	return nil
}

func (ipHandler *handler) DeletePortFromServerPortSet(contextID string, port string) error {

	ips := getIpset(ipHandler.getServerPortSetName(contextID))

	if err := ips.Del(port); err != nil {
		return fmt.Errorf("unable to delete port from portset: %s", err)
	}

	return nil
}

// RegisterExternalNets registers the contextID and the corresponding serviceIDs
func (ipHandler *handler) RegisterExternalNets(contextID string, extnets policy.IPRuleList) error {
	ipHandler.Lock()
	defer ipHandler.Unlock()

	processExtnets := func() error {
		for _, extnet := range extnets {
			var ipset *ipsetInfo

			serviceID := extnet.Policy.ServiceID
			if ipset = ipHandler.acl.serviceIDtoACLIPset[serviceID]; ipset == nil {
				var err error
				if ipset, err = ipHandler.createACLIPset(serviceID); err != nil {
					return err
				}
			}

			// make sure to include updates that were added dynamically by the DNS proxy
			addrs := extnet.Addresses
			if dynamicAddrs, ok := ipHandler.dynamicUpdates[serviceID]; ok {
				addrs = append(addrs, dynamicAddrs...)
			}

			ipHandler.synchronizeIPsinIpset(ipset, addrs)
			// have a backreference from serviceID to contextID
			ipset.contextIDs[contextID] = true
		}

		return nil
	}

	processOlderExtnets := func() {
		newExtnets := map[string]bool{}

		for _, extnet := range extnets {

			serviceID := extnet.Policy.ServiceID
			newExtnets[serviceID] = true
			m, ok := ipHandler.acl.contextIDtoServiceIDs[contextID]

			if ok && m[serviceID] {
				delete(m, serviceID)
			}
		}

		for serviceID := range ipHandler.acl.contextIDtoServiceIDs[contextID] {
			ipHandler.reduceReferenceFromServiceID(contextID, serviceID)
		}

		ipHandler.acl.contextIDtoServiceIDs[contextID] = newExtnets
	}

	if err := processExtnets(); err != nil {
		return err
	}

	processOlderExtnets()

	return nil
}

// deleteDynamicAddresses must only be alled by DeleteEntryFromIPset to update the internal map of dyanamic addresses
func (ipHandler *handler) deleteDynamicAddresses(ips []string, serviceID string) {
	if dynAddrs, ok := ipHandler.dynamicUpdates[serviceID]; ok {
		ipMap := make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			ipMap[ip] = struct{}{}
		}

		newAddrs := make([]string, 0, len(dynAddrs))
		for _, dynAddr := range dynAddrs {
			if _, ok := ipMap[dynAddr]; ok {
				continue
			}
			newAddrs = append(newAddrs, dynAddr)
		}

		ipHandler.dynamicUpdates[serviceID] = newAddrs
	}
}

// DeleteEntryFromIPset delete an entry from an ipset
func (ipHandler *handler) DeleteEntryFromIPset(ips []string, serviceID string) {
	ipHandler.Lock()
	defer ipHandler.Unlock()

	ipHandler.deleteDynamicAddresses(ips, serviceID)

	for _, address := range ips {
		parsableAddress := address
		if strings.HasPrefix(address, "!") {
			parsableAddress = address[1:]
		}

		netIP := net.ParseIP(parsableAddress)
		if netIP == nil {
			netIP, _, _ = net.ParseCIDR(parsableAddress)
		}
		if ipset := ipHandler.acl.serviceIDtoACLIPset[serviceID]; ipset != nil {
			ipsetHandler := getIpset(ipset.name)
			delFromIPset(ipsetHandler, netIP.String()) // nolint
			delete(ipset.addresses, address)

		}

	}
}

// updateDynamicAddresses must only be called by UpdateACLIPsets to update the internal map of dynamic addresses
func (ipHandler *handler) updateDynamicAddresses(addresses []string, serviceID string) {
	// no need to lock, already done by the caller
	if dynAddrs, ok := ipHandler.dynamicUpdates[serviceID]; ok {
		ipMap := make(map[string]struct{}, len(dynAddrs))
		for _, ip := range dynAddrs {
			ipMap[ip] = struct{}{}
		}

		newAddrs := make([]string, 0, len(addresses))
		for _, ip := range addresses {
			if _, ok := ipMap[ip]; ok {
				continue
			}
			newAddrs = append(newAddrs, ip)
		}

		ipHandler.dynamicUpdates[serviceID] = append(dynAddrs, newAddrs...)
	} else {
		ipHandler.dynamicUpdates[serviceID] = addresses
	}
}

//UpdateACLIPsets updates the ip addresses in the ipsets corresponding to the serviceID
func (ipHandler *handler) UpdateACLIPsets(addresses []string, serviceID string) {
	ipHandler.Lock()
	defer ipHandler.Unlock()

	ipHandler.updateDynamicAddresses(addresses, serviceID)

	for _, address := range addresses {
		parsableAddress := address
		if strings.HasPrefix(address, "!") {
			parsableAddress = address[1:]
		}

		netIP := net.ParseIP(parsableAddress)
		if netIP == nil {
			netIP, _, _ = net.ParseCIDR(parsableAddress)
		}

		if !ipHandler.ipFilter(netIP) {
			continue
		}

		if ipset := ipHandler.acl.serviceIDtoACLIPset[serviceID]; ipset != nil {
			ipsetHandler := getIpset(ipset.name)
			if err := addToIPset(ipsetHandler, address); err != nil {
				zap.L().Error("Error adding IPs to ipset", zap.String("ipset", ipset.name), zap.String("address", address))
			}

			ipset.addresses[address] = true
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

func (ipHandler *handler) synchronizeIPsinIpset(ipsetInfo *ipsetInfo, addresses []string) {
	newips := map[string]bool{}
	ipsetHandler := getIpset(ipsetInfo.name)

	var addrToAdd, addrToDelete []string

	for _, address := range addresses {
		parsableAddress := address
		if strings.HasPrefix(address, "!") {
			parsableAddress = address[1:]
		}

		netIP := net.ParseIP(parsableAddress)
		if netIP == nil {
			netIP, _, _ = net.ParseCIDR(parsableAddress)
		}

		if !ipHandler.ipFilter(netIP) {
			continue
		}

		newips[address] = true

		if _, ok := ipsetInfo.addresses[address]; !ok {
			addrToAdd = append(addrToAdd, address)
		}
		delete(ipsetInfo.addresses, address)
	}

	for address, val := range ipsetInfo.addresses {
		if val {
			addrToDelete = append(addrToDelete, address)
		}
	}

	if err := updateIPSets(ipsetHandler, addrToDelete, addrToAdd); err != nil {
		zap.L().Error("Error updating ipset during sync", zap.Error(err))
	}

	ipsetInfo.addresses = newips
}

func (ipHandler *handler) createACLIPset(serviceID string) (*ipsetInfo, error) {
	ipsetName := ipHandler.ipsetPrefix + "ext-" + hashServiceID(serviceID)
	if _, err := newIpset(ipsetName, "hash:net", ipHandler.ipsetParams); err != nil {
		return nil, err
	}

	ipset := &ipsetInfo{contextIDs: map[string]bool{}, name: ipsetName, addresses: map[string]bool{}}
	ipHandler.acl.serviceIDtoACLIPset[serviceID] = ipset

	return ipset, nil
}

func (ipHandler *handler) deleteServiceID(serviceID string) {
	ipsetInfo := ipHandler.acl.serviceIDtoACLIPset[serviceID]
	ipHandler.acl.toDestroy = append(ipHandler.acl.toDestroy, ipsetInfo.name)
	delete(ipHandler.acl.serviceIDtoACLIPset, serviceID)
}

//reduceReferenceFromServiceID reduces the reference for the serviceID.
func (ipHandler *handler) reduceReferenceFromServiceID(contextID string, serviceID string) {
	var ipset *ipsetInfo

	if ipset = ipHandler.acl.serviceIDtoACLIPset[serviceID]; ipset == nil {
		zap.L().Error("Could not find ipset corresponding to serviceID", zap.String("serviceID", serviceID))
		return
	}

	delete(ipset.contextIDs, contextID)

	// there are no references from any pu. safe to destroy now
	if len(ipset.contextIDs) == 0 {
		ipHandler.deleteServiceID(serviceID)
	}
}

// DestroyUnusedIPsets destroys the unused ipsets.
func (ipHandler *handler) DestroyUnusedIPsets() {
	ipHandler.Lock()
	defer ipHandler.Unlock()

	for _, ipsetName := range ipHandler.acl.toDestroy {
		ipsetHandler := getIpset(ipsetName)
		if err := ipsetHandler.Destroy(); err != nil {
			zap.L().Warn("Failed to destroy ipset", zap.String("ipset", ipsetName), zap.Error(err))
		}
	}

	ipHandler.acl.toDestroy = nil
}

// RemoveExternalNets is called when the contextID is being unsupervised such that all the external nets can be deleted.
func (ipHandler *handler) RemoveExternalNets(contextID string) {
	ipHandler.Lock()

	m, ok := ipHandler.acl.contextIDtoServiceIDs[contextID]
	if ok {
		for serviceID := range m {
			ipHandler.reduceReferenceFromServiceID(contextID, serviceID)
		}
	}

	delete(ipHandler.acl.contextIDtoServiceIDs, contextID)

	ipHandler.Unlock()
	ipHandler.DestroyUnusedIPsets()
}

func (ipHandler *handler) GetIPsetPrefix() string {
	return ipHandler.ipsetPrefix
}

// GetACLIPsets returns the ipset names corresponding to the serviceIDs.
func (ipHandler *handler) GetACLIPsetsNames(extnets policy.IPRuleList) []string {

	ipHandler.Lock()
	defer ipHandler.Unlock()

	var ipsets []string

	for _, extnet := range extnets {
		serviceID := extnet.Policy.ServiceID

		ipsetInfo, ok := ipHandler.acl.serviceIDtoACLIPset[serviceID]
		if ok {
			ipsets = append(ipsets, ipsetInfo.name)
		}
	}

	return ipsets
}

//createName takes the contextID and prefix and returns a name after processing
func createName(contextID string, prefix string) string {
	hash := murmur3.New64()

	if _, err := io.WriteString(hash, contextID); err != nil {
		return ""
	}

	output := base64.URLEncoding.EncodeToString(hash.Sum(nil))

	if len(contextID) > 4 {
		contextID = contextID[:4] + output[:4]
	} else {
		contextID = contextID + output[:4]
	}

	if len(prefix) > 16 {
		prefix = prefix[:16]
	}

	return (prefix + contextID)
}

//V4test returns the test handler for ipv4
func V4test() IPSetManager {
	return &handler{
		ipsetPrefix: "TRI-" + ipv4String,
		ipFilter: func(ip net.IP) bool {
			return (ip.To4() != nil)
		},
		ipsetParams: &ipsetpackage.Params{},

		acl: aclHandler{
			serviceIDtoACLIPset:   map[string]*ipsetInfo{},
			contextIDtoServiceIDs: map[string]map[string]bool{},
		},
		tn: targetNetwork{tcp: []string{}, udp: []string{}},
		en: excludedNetwork{excluded: []string{}},
	}
}

//V6test returns the test handler for ipv6
func V6test() IPSetManager {
	return &handler{
		ipsetPrefix: "TRI-" + ipv6String,
		ipFilter: func(ip net.IP) bool {
			return (ip.To4() == nil)
		},
		ipsetParams: &ipsetpackage.Params{HashFamily: "inet6"},

		acl: aclHandler{
			serviceIDtoACLIPset:   map[string]*ipsetInfo{},
			contextIDtoServiceIDs: map[string]map[string]bool{},
		},
		tn: targetNetwork{tcp: []string{}, udp: []string{}},
		en: excludedNetwork{excluded: []string{}},
	}
}
