package supervisor

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
)

const (
	chainPrefix                = "TRIREME-"
	appPacketIPTableContext    = "raw"
	appAckPacketIPTableContext = "mangle"
	appPacketIPTableSection    = "PREROUTING"
	appChainPrefix             = chainPrefix + "App-"
	netPacketIPTableContext    = "mangle"
	netPacketIPTableSection    = "POSTROUTING"
	netChainPrefix             = chainPrefix + "Net-"
)

type supervisorCacheEntry struct {
	index       int
	ips         map[string]string
	ingressACLs []policy.IPRule
	egressACLs  []policy.IPRule
}

// iptablesSupervisor is the structure holding all information about a connection filter
type iptablesSupervisor struct {
	versionTracker    cache.DataStore
	ipt               *iptables.IPTables
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	targetNetworks    []string
}

// NewIPTablesSupervisor will create a new connection supervisor that uses IPTables
// to redirect specific packets to userspace. It instantiates multiple data stores
// to maintain efficient mappings between contextID, policy and IP addresses. This
// simplifies the lookup operations at the expense of memory.
func NewIPTablesSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, targetNetworks []string) Supervisor {

	filterQueue := enforcer.GetFilterQueue()

	s := &iptablesSupervisor{
		versionTracker:    cache.NewCache(nil),
		targetNetworks:    targetNetworks,
		collector:         collector,
		networkQueues:     strconv.Itoa(int(filterQueue.NetworkQueue)) + ":" + strconv.Itoa(int(filterQueue.NetworkQueue+filterQueue.NumberOfNetworkQueues-1)),
		applicationQueues: strconv.Itoa(int(filterQueue.ApplicationQueue)) + ":" + strconv.Itoa(int(filterQueue.ApplicationQueue+filterQueue.NumberOfApplicationQueues-1)),
	}

	// Make sure that the iptables command is accessible. Panic if its not there.
	var err error
	s.ipt, err = iptables.New()
	if err != nil {
		panic("Can't find iptables command")
	}

	// Clean any previous ACLs that we have installed
	s.CleanACL()

	return s
}

// AddPU creates a mapping between an IP address and the corresponding labels
// and the invokes the various handlers that process all policies.
func (s *iptablesSupervisor) Supervise(contextID string, containerInfo *policy.PUInfo) error {
	_, err := s.versionTracker.Get(contextID)
	if err != nil {
		glog.V(2).Infoln("ContextID Already exist in Cache. Do update")
		return s.doUpdatePU(contextID, containerInfo)
	}
	return s.doCreatePU(contextID, containerInfo)
}

func (s *iptablesSupervisor) doCreatePU(contextID string, container *policy.PUInfo) error {

	index := 0

	appChain := appChainPrefix + contextID + "-" + strconv.Itoa(index)
	netChain := netChainPrefix + contextID + "-" + strconv.Itoa(index)

	// Currently processing only containers with one IP address
	ipAddress, ok := container.Runtime.DefaultIPAddress()
	if !ok {
		return fmt.Errorf("Container IP address not found")
	}

	cacheEntry := &supervisorCacheEntry{
		index:       index,
		ips:         container.Runtime.IPAddresses(),
		ingressACLs: container.Policy.IngressACLs,
		egressACLs:  container.Policy.EgressACLs,
	}

	// Version the policy so that we can do hitless policy changes
	if err := s.versionTracker.AddOrUpdate(contextID, cacheEntry); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	// Configure all the ACLs
	if err := s.addContainerChain(appChain, netChain); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	if err := s.addChainRules(appChain, netChain, ipAddress); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	if err := s.addPacketTrap(appChain, netChain, ipAddress); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	if err := s.addAppACLs(appChain, ipAddress, container.Policy.IngressACLs); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	if err := s.addNetACLs(netChain, ipAddress, container.Policy.IngressACLs); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	ip, _ := container.Runtime.DefaultIPAddress()
	s.collector.CollectContainerEvent(contextID, ip, container.Runtime.Tags(), "start")

	return nil
}

//UpdatePU creates a mapping between an IP address and the corresponding labels
//and the invokes the various handlers that process all policies.
func (s *iptablesSupervisor) doUpdatePU(contextID string, containerInfo *policy.PUInfo) error {

	cacheEntry, err := s.versionTracker.LockedModify(contextID, add, 1)
	newindex := cacheEntry.(*supervisorCacheEntry).index
	oldindex := newindex - 1

	result, err := s.versionTracker.Get(contextID)
	if err != nil {
		return err
	}
	cachedEntry := result.(*supervisorCacheEntry)

	// Currently processing only containers with one IP address
	ipAddress, ok := cachedEntry.ips["bridge"]
	if !ok {
		return fmt.Errorf("Container IP address not found!")
	}

	appChain := appChainPrefix + contextID + "-" + strconv.Itoa(newindex)
	netChain := netChainPrefix + contextID + "-" + strconv.Itoa(newindex)

	oldAppChain := appChainPrefix + contextID + "-" + strconv.Itoa(oldindex)
	oldNetChain := netChainPrefix + contextID + "-" + strconv.Itoa(oldindex)

	//Add a new chain for this update and map all rules there
	if err := s.addContainerChain(appChain, netChain); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	if err := s.addPacketTrap(appChain, netChain, ipAddress); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	if err := s.addAppACLs(appChain, ipAddress, containerInfo.Policy.IngressACLs); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	if err := s.addNetACLs(netChain, ipAddress, containerInfo.Policy.EgressACLs); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	// Add mapping to new chain
	if err := s.addChainRules(appChain, netChain, ipAddress); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	//Remove mapping from old chain
	if err := s.deleteChainRules(oldAppChain, oldNetChain, ipAddress); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	// Delete the old chain to clean up
	if err := s.deleteAllContainerChains(oldAppChain, oldNetChain); err != nil {
		s.Unsupervise(contextID)
		return err
	}

	ip, _ := containerInfo.Runtime.DefaultIPAddress()
	s.collector.CollectContainerEvent(contextID, ip, containerInfo.Runtime.Tags(), "update")

	return nil
}

// Unsupervise removes the mapping from cache and cleans up the iptable rules. ALL
// remove operations will print errors by they don't return error. We want to force
// as much cleanup as possible to avoid stale state
func (s *iptablesSupervisor) Unsupervise(contextID string) error {

	result, err := s.versionTracker.Get(contextID)
	if err != nil {
		return fmt.Errorf("Cannot find policy version!")
	}
	cacheEntry := result.(*supervisorCacheEntry)

	appChain := appChainPrefix + contextID + "-" + strconv.Itoa(cacheEntry.index)
	netChain := netChainPrefix + contextID + "-" + strconv.Itoa(cacheEntry.index)

	// Currently processing only containers with one IP address
	ip, ok := cacheEntry.ips["bridge"]
	if !ok {
		return fmt.Errorf("Container IP address not found!")
	}

	s.deletePacketTrap(appChain, netChain, ip)

	s.deleteAppACLs(appChain, ip, cacheEntry.ingressACLs)

	s.deleteNetACLs(netChain, ip, cacheEntry.egressACLs)

	s.deleteChainRules(appChain, netChain, ip)

	s.deleteAllContainerChains(appChain, netChain)

	s.versionTracker.Remove(contextID)

	return nil
}

// CleanACL cleans up all the ACLs that have an Trireme  Label in the mangle table
func (s *iptablesSupervisor) CleanACL() {

	// Clean Application Rules/Chains
	s.cleanACLSection(appPacketIPTableContext, appPacketIPTableSection, chainPrefix)

	// Clean Application Rules/Chains
	s.cleanACLSection(appAckPacketIPTableContext, appPacketIPTableSection, chainPrefix)

	// Clean Application Rules/Chains
	s.cleanACLSection(appAckPacketIPTableContext, appPacketIPTableSection, chainPrefix)

	// Clean Network Rules/Chains
	s.cleanACLSection(netPacketIPTableContext, netPacketIPTableSection, chainPrefix)
}

// Start starts the supervisor
func (s *iptablesSupervisor) Start() error {
	return nil
}

// Stop stops the supervisor
func (s *iptablesSupervisor) Stop() error {
	// Clean any previous ACLs that we have installed
	s.CleanACL()
	return nil
}

// addContainerChain adds a chain for the specific container and redirects traffic there
// This simplifies significantly the management and makes the iptable rules more readable
// All rules related to a container are contained within the dedicated chain
func (s *iptablesSupervisor) addContainerChain(appChain string, netChain string) error {

	if err := s.ipt.NewChain(appPacketIPTableContext, appChain); err != nil {
		glog.V(2).Infoln("Failed to create container specific chain", appChain, err)
		return err
	}

	if err := s.ipt.NewChain(appAckPacketIPTableContext, appChain); err != nil {
		glog.V(2).Infoln("Failed to create container specific chain", appChain, err)
		return err
	}

	if err := s.ipt.NewChain(netPacketIPTableContext, netChain); err != nil {
		glog.V(2).Infoln("Failed to create container specific chain", netChain, err)
		return err
	}
	return nil
}

// delete removes all the rules in the provided chain and deletes the
// chain
func (s *iptablesSupervisor) deleteChain(context, chain string) error {

	if err := s.ipt.ClearChain(context, chain); err != nil {
		glog.V(2).Infoln("Failed to clear the container specific chain: ", chain, err)
		return err
	}

	if err := s.ipt.DeleteChain(context, chain); err != nil {
		glog.V(2).Infoln("Failed to delete the container specific chain ", chain, err)
		return err
	}

	return nil
}

// deleteAllContainerChains removes all the container specific chains and basic rules
func (s *iptablesSupervisor) deleteAllContainerChains(appChain, netChain string) error {

	if err := s.deleteChain(appPacketIPTableContext, appChain); err != nil {
		glog.V(2).Infoln("Failed to clear and delete the appChain: ", appChain, err)
	}

	if err := s.deleteChain(appAckPacketIPTableContext, appChain); err != nil {
		glog.V(2).Infoln("Failed to clear and delete the appChain: ", appChain, err)
	}

	if err := s.deleteChain(netPacketIPTableContext, netChain); err != nil {
		glog.V(2).Infoln("Failed to clear and delete the netChain: ", netChain, err)
	}

	return nil
}

// chainRules provides the list of rules that are used to send traffic to
// a particular chain
func (s *iptablesSupervisor) chainRules(appChain string, netChain string, ip string) [][]string {

	chainRules := [][]string{
		{
			appPacketIPTableContext,
			appPacketIPTableSection,
			"-s", ip,
			"-i", "docker0",
			"-m", "comment", "--comment", "Container specific chain",
			"-j", appChain,
		},
		{appAckPacketIPTableContext,
			appPacketIPTableSection,
			"-s", ip,
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-i", "docker0",
			"-m", "comment", "--comment", "Container specific chain",
			"-j", appChain,
		},
		{
			netPacketIPTableContext,
			netPacketIPTableSection,
			"-d", ip,
			"-m", "comment", "--comment", "Container specific chain",
			"-j", netChain,
		},
	}

	return chainRules
}

// addChains rules implements all the iptable rules that redirect traffic to a chain
func (s *iptablesSupervisor) addChainRules(appChain string, netChain string, ip string) error {

	chainRules := s.chainRules(appChain, netChain, ip)
	for _, cr := range chainRules {

		if err := s.ipt.Append(cr[0], cr[1], cr[2:]...); err != nil {
			glog.V(2).Infoln("Failed to create "+cr[0]+":"+cr[1]+" rule that redirects to container chain", err)
			return err
		}
	}

	return nil
}

//deleteChainRules deletes the rules that send traffic to our chain
func (s *iptablesSupervisor) deleteChainRules(appChain, netChain, ip string) error {

	chainRules := s.chainRules(appChain, netChain, ip)
	for _, cr := range chainRules {

		if err := s.ipt.Delete(cr[0], cr[1], cr[2:]...); err != nil {
			glog.V(2).Infoln("Failed to delete "+cr[0]+":"+cr[1]+" rule that redirects to container chain", err)
			return err
		}
	}

	return nil
}

//trapRules provides the packet trap rules to add/delete
func (s *iptablesSupervisor) trapRules(appChain string, netChain string, network string) [][]string {

	trapRules := [][]string{
		// Application Syn and Syn/Ack
		{
			appPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "NFQUEUE", "--queue-balance", s.applicationQueues,
		},

		// Application everything else
		{
			appAckPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", s.applicationQueues,
		},

		// Network side rules
		{
			netPacketIPTableContext, netChain,
			"-s", network,
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", s.networkQueues,
		},
	}

	return trapRules
}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (s *iptablesSupervisor) addPacketTrap(appChain string, netChain string, ip string) error {

	for _, network := range s.targetNetworks {

		trapRules := s.trapRules(appChain, netChain, network)
		for _, tr := range trapRules {

			if err := s.ipt.Append(tr[0], tr[1], tr[2:]...); err != nil {
				glog.V(2).Infoln("Failed to create "+tr[0]+":"+tr[1]+" rule that redirects to container chain", err)
				return err
			}
		}
	}

	return nil
}

// deletePacketTrap deletes the iptables rules that trap control  packets to user space
func (s *iptablesSupervisor) deletePacketTrap(appChain, netChain, ip string) error {

	for _, network := range s.targetNetworks {

		trapRules := s.trapRules(appChain, netChain, network)
		for _, tr := range trapRules {

			if err := s.ipt.Append(tr[0], tr[1], tr[2:]...); err != nil {
				glog.V(2).Infoln("Failed to delete "+tr[0]+":"+tr[1]+" rule that redirects to container chain", err)
				return err
			}
		}
	}

	return nil
}

// addAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (s *iptablesSupervisor) addAppACLs(chain string, ip string, rules []policy.IPRule) error {

	for i := range rules {

		if err := s.ipt.Insert(
			appPacketIPTableContext, chain, 1,
			"-p", rules[i].Protocol,
			"-d", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			glog.V(2).Infoln("Error adding rule ", rules[i], err)
			return err
		}

	}

	if err := s.ipt.Append(
		appPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP"); err != nil {
		glog.V(2).Infoln("Error adding default rule ! ", err)
		return err
	}

	return nil
}

// deleteAppACLs deletes the rules associated with traffic to external services
func (s *iptablesSupervisor) deleteAppACLs(chain string, ip string, rules []policy.IPRule) error {

	for i := range rules {
		if err := s.ipt.Delete(
			appPacketIPTableContext, chain,
			"-p", rules[i].Protocol,
			"-d", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			glog.V(2).Infoln("Error removing ingress ACL rule ", rules[i], err)
		}
	}

	if err := s.ipt.Delete(
		appPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		glog.V(2).Infoln("Error removing default ingress ACL rule  ! ", err)

	}

	return nil
}

// addNetACLs adds iptables rules that manage traffic from external services. The
// explicit rules are added with the higest priority since they are direct allows.
func (s *iptablesSupervisor) addNetACLs(chain, ip string, rules []policy.IPRule) error {

	for i := range rules {

		if err := s.ipt.Insert(
			netPacketIPTableContext, chain, 1,
			"-p", rules[i].Protocol,
			"-s", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			glog.V(2).Infoln("Error adding rule ", rules[i], err)
			return err
		}

	}

	if err := s.ipt.Append(
		netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		glog.V(2).Infoln("Error adding default rule ! ", err)
		return err
	}

	return nil
}

// deleteNetACLs removes the iptable rules that manage traffic from external services
func (s *iptablesSupervisor) deleteNetACLs(chain string, ip string, rules []policy.IPRule) error {

	for i := range rules {
		if err := s.ipt.Delete(
			netPacketIPTableContext, chain,
			"-p", rules[i].Protocol,
			"-s", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			glog.V(2).Infoln("Error removing egress ACL rule ", rules[i], err)
		}
	}

	if err := s.ipt.Delete(
		netPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		glog.V(2).Infoln("Error removing default ACL rule  ! ", err)
	}

	return nil
}

func (s *iptablesSupervisor) cleanACLSection(context, section, chainPrefix string) {

	if err := s.ipt.ClearChain(context, section); err != nil {
		glog.V(2).Infoln("Can't clear ", section, " iptables command")
		return
	}

	rules, err := s.ipt.ListChains(context)
	if err != nil {
		glog.V(5).Infoln("No chain rules found")
		return
	}

	for _, rule := range rules {

		if strings.Contains(rule, chainPrefix) {
			s.ipt.ClearChain(context, rule)
			s.ipt.DeleteChain(context, rule)
		}
	}
}

func add(a, b interface{}) interface{} {
	entry := a.(*supervisorCacheEntry)
	entry.index += b.(int)
	return entry
}
