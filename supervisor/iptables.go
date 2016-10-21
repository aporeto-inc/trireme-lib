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

type supervisorCacheEntry struct {
	index       int
	ips         map[string]string
	ingressACLs []policy.IPRule
	egressACLs  []policy.IPRule
}

// iptablesSupervisor is the structure holding all information about a connection filter
type iptablesSupervisor struct {
	versionTracker cache.DataStore

	// Engine components
	ipt       *iptables.IPTables
	collector collector.EventCollector

	// NFQUEUE configuration
	networkQueues     string
	applicationQueues string

	// List of destination networks that require Trireme controls
	targetNetworks []string
}

// NewIPTablesSupervisor will create a new connection supervisor. It instantiates multiple data stores
// to maintain efficient mappings between contextID, policy and IP addresses. This
// simplifies the lookup operations at the expense of memory.
func NewIPTablesSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, targetNetworks []string) Supervisor {

	filterQueue := enforcer.GetFilterQueue()

	c := &iptablesSupervisor{
		versionTracker:    cache.NewCache(nil),
		targetNetworks:    targetNetworks,
		collector:         collector,
		networkQueues:     strconv.Itoa(int(filterQueue.NetworkQueue)) + ":" + strconv.Itoa(int(filterQueue.NetworkQueue+filterQueue.NumberOfNetworkQueues-1)),
		applicationQueues: strconv.Itoa(int(filterQueue.ApplicationQueue)) + ":" + strconv.Itoa(int(filterQueue.ApplicationQueue+filterQueue.NumberOfApplicationQueues-1)),
	}

	// Make sure that the iptables command is accessible. Panic if its not there.
	var err error
	c.ipt, err = iptables.New()
	if err != nil {
		panic("Can't find iptables command")
	}

	// Clean any previous ACLs that we have installed
	c.CleanACL()

	return c
}

// AddPU creates a mapping between an IP address and the corresponding labels
// and the invokes the various handlers that process all policies.
func (c *iptablesSupervisor) AddPU(contextID string, container *policy.PUInfo) error {

	index := 0

	appChain := triremeAppChainPrefix + contextID + "-" + strconv.Itoa(index)
	netChain := triremeNetChainPrefix + contextID + "-" + strconv.Itoa(index)

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
	if err := c.versionTracker.AddOrUpdate(contextID, cacheEntry); err != nil {
		c.DeletePU(contextID)
		return err
	}

	// Configure all the ACLs
	if err := c.addContainerChain(appChain, netChain); err != nil {
		c.DeletePU(contextID)
		return err
	}

	if err := c.addChainRules(appChain, netChain, ipAddress); err != nil {
		c.DeletePU(contextID)
		return err
	}

	if err := c.addPacketTrap(appChain, netChain, ipAddress); err != nil {
		c.DeletePU(contextID)
		return err
	}

	if err := c.addAppACLs(appChain, ipAddress, container.Policy.IngressACLs); err != nil {
		c.DeletePU(contextID)
		return err
	}

	if err := c.addNetACLs(netChain, ipAddress, container.Policy.IngressACLs); err != nil {
		c.DeletePU(contextID)
		return err
	}

	ip, _ := container.Runtime.DefaultIPAddress()
	c.collector.CollectContainerEvent(contextID, ip, container.Runtime.Tags(), "start")

	return nil
}

//UpdatePU creates a mapping between an IP address and the corresponding labels
//and the invokes the various handlers that process all policies.
func (c *iptablesSupervisor) UpdatePU(contextID string, containerInfo *policy.PUInfo) error {

	cacheEntry, err := c.versionTracker.LockedModify(contextID, add, 1)
	newindex := cacheEntry.(*supervisorCacheEntry).index
	oldindex := newindex - 1

	result, err := c.versionTracker.Get(contextID)
	if err != nil {
		return err
	}
	cachedEntry := result.(*supervisorCacheEntry)

	// Currently processing only containers with one IP address
	ipAddress, ok := cachedEntry.ips["bridge"]
	if !ok {
		return fmt.Errorf("Container IP address not found!")
	}

	appChain := triremeAppChainPrefix + contextID + "-" + strconv.Itoa(newindex)
	netChain := triremeNetChainPrefix + contextID + "-" + strconv.Itoa(newindex)

	oldAppChain := triremeAppChainPrefix + contextID + "-" + strconv.Itoa(oldindex)
	oldNetChain := triremeNetChainPrefix + contextID + "-" + strconv.Itoa(oldindex)

	//Add a new chain for this update and map all rules there
	if err := c.addContainerChain(appChain, netChain); err != nil {
		c.DeletePU(contextID)
		return err
	}

	if err := c.addPacketTrap(appChain, netChain, ipAddress); err != nil {
		c.DeletePU(contextID)
		return err
	}

	if err := c.addAppACLs(appChain, ipAddress, containerInfo.Policy.IngressACLs); err != nil {
		c.DeletePU(contextID)
		return err
	}

	if err := c.addNetACLs(netChain, ipAddress, containerInfo.Policy.EgressACLs); err != nil {
		c.DeletePU(contextID)
		return err
	}

	// Add mapping to new chain
	if err := c.addChainRules(appChain, netChain, ipAddress); err != nil {
		c.DeletePU(contextID)
		return err
	}

	//Remove mapping from old chain
	if err := c.deleteChainRules(oldAppChain, oldNetChain, ipAddress); err != nil {
		c.DeletePU(contextID)
		return err
	}

	// Delete the old chain to clean up
	if err := c.deleteAllContainerChains(oldAppChain, oldNetChain); err != nil {
		c.DeletePU(contextID)
		return err
	}

	ip, _ := containerInfo.Runtime.DefaultIPAddress()
	c.collector.CollectContainerEvent(contextID, ip, containerInfo.Runtime.Tags(), "update")

	return nil
}

// DeletePU removes the mapping from cache and cleans up the iptable rules. ALL
// remove operations will print errors by they don't return error. We want to force
// as much cleanup as possible to avoid stale state
func (c *iptablesSupervisor) DeletePU(contextID string) error {

	result, err := c.versionTracker.Get(contextID)
	if err != nil {
		return fmt.Errorf("Cannot find policy version!")
	}
	cacheEntry := result.(*supervisorCacheEntry)

	appChain := triremeAppChainPrefix + contextID + "-" + strconv.Itoa(cacheEntry.index)
	netChain := triremeNetChainPrefix + contextID + "-" + strconv.Itoa(cacheEntry.index)

	// Currently processing only containers with one IP address
	ip, ok := cacheEntry.ips["bridge"]
	if !ok {
		return fmt.Errorf("Container IP address not found!")
	}

	c.deletePacketTrap(appChain, netChain, ip)

	c.deleteAppACLs(appChain, ip, cacheEntry.ingressACLs)

	c.deleteNetACLs(netChain, ip, cacheEntry.egressACLs)

	c.deleteChainRules(appChain, netChain, ip)

	c.deleteAllContainerChains(appChain, netChain)

	c.versionTracker.Remove(contextID)

	return nil
}

// CleanACL cleans up all the ACLs that have an Trireme  Label in the mangle table
func (c *iptablesSupervisor) CleanACL() {

	// Clean Application Rules/Chains
	c.cleanACLSection(triremeAppPacketIPTableContext, triremeAppPacketIPTableSection, triremeChainPrefix)

	// Clean Application Rules/Chains
	c.cleanACLSection(triremeAppAckPacketIPTableContext, triremeAppPacketIPTableSection, triremeChainPrefix)

	// Clean Application Rules/Chains
	c.cleanACLSection(triremeAppAckPacketIPTableContext, triremeAppPacketIPTableSection, triremeChainPrefix)

	// Clean Network Rules/Chains
	c.cleanACLSection(triremeNetPacketIPTableContext, triremeNetPacketIPTableSection, triremeChainPrefix)
}

// Start starts the supervisor
func (c *iptablesSupervisor) Start() error {
	return nil
}

// Stop stops the supervisor
func (c *iptablesSupervisor) Stop() error {
	// Clean any previous ACLs that we have installed
	c.CleanACL()
	return nil
}

// addContainerChain adds a chain for the specific container and redirects traffic there
// This simplifies significantly the management and makes the iptable rules more readable
// All rules related to a container are contained within the dedicated chain
func (c *iptablesSupervisor) addContainerChain(appChain string, netChain string) error {

	if err := c.ipt.NewChain(triremeAppPacketIPTableContext, appChain); err != nil {
		glog.V(2).Infoln("Failed to create container specific chain", appChain, err)
		return err
	}

	if err := c.ipt.NewChain(triremeAppAckPacketIPTableContext, appChain); err != nil {
		glog.V(2).Infoln("Failed to create container specific chain", appChain, err)
		return err
	}

	if err := c.ipt.NewChain(triremeNetPacketIPTableContext, netChain); err != nil {
		glog.V(2).Infoln("Failed to create container specific chain", netChain, err)
		return err
	}
	return nil
}

// delete removes all the rules in the provided chain and deletes the
// chain
func (c *iptablesSupervisor) deleteChain(context, chain string) error {

	if err := c.ipt.ClearChain(context, chain); err != nil {
		glog.V(2).Infoln("Failed to clear the container specific chain: ", chain, err)
		return err
	}

	if err := c.ipt.DeleteChain(context, chain); err != nil {
		glog.V(2).Infoln("Failed to delete the container specific chain ", chain, err)
		return err
	}

	return nil
}

// deleteAllContainerChains removes all the container specific chains and basic rules
func (c *iptablesSupervisor) deleteAllContainerChains(appChain, netChain string) error {

	if err := c.deleteChain(triremeAppPacketIPTableContext, appChain); err != nil {
		glog.V(2).Infoln("Failed to clear and delete the appChain: ", appChain, err)
	}

	if err := c.deleteChain(triremeAppAckPacketIPTableContext, appChain); err != nil {
		glog.V(2).Infoln("Failed to clear and delete the appChain: ", appChain, err)
	}

	if err := c.deleteChain(triremeNetPacketIPTableContext, netChain); err != nil {
		glog.V(2).Infoln("Failed to clear and delete the netChain: ", netChain, err)
	}

	return nil
}

// chainRules provides the list of rules that are used to send traffic to
// a particular chain
func (c *iptablesSupervisor) chainRules(appChain string, netChain string, ip string) [][]string {

	chainRules := [][]string{
		{
			triremeAppPacketIPTableContext,
			triremeAppPacketIPTableSection,
			"-s", ip,
			"-i", "docker0",
			"-m", "comment", "--comment", "Container specific chain",
			"-j", appChain,
		},
		{triremeAppAckPacketIPTableContext,
			triremeAppPacketIPTableSection,
			"-s", ip,
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-i", "docker0",
			"-m", "comment", "--comment", "Container specific chain",
			"-j", appChain,
		},
		{
			triremeNetPacketIPTableContext,
			triremeNetPacketIPTableSection,
			"-d", ip,
			"-m", "comment", "--comment", "Container specific chain",
			"-j", netChain,
		},
	}

	return chainRules
}

// addChains rules implements all the iptable rules that redirect traffic to a chain
func (c *iptablesSupervisor) addChainRules(appChain string, netChain string, ip string) error {

	chainRules := c.chainRules(appChain, netChain, ip)
	for _, cr := range chainRules {

		if err := c.ipt.Append(cr[0], cr[1], cr[2:]...); err != nil {
			glog.V(2).Infoln("Failed to create "+cr[0]+":"+cr[1]+" rule that redirects to container chain", err)
			return err
		}
	}

	return nil
}

//deleteChainRules deletes the rules that send traffic to our chain
func (c *iptablesSupervisor) deleteChainRules(appChain, netChain, ip string) error {

	chainRules := c.chainRules(appChain, netChain, ip)
	for _, cr := range chainRules {

		if err := c.ipt.Delete(cr[0], cr[1], cr[2:]...); err != nil {
			glog.V(2).Infoln("Failed to delete "+cr[0]+":"+cr[1]+" rule that redirects to container chain", err)
			return err
		}
	}

	return nil
}

//trapRules provides the packet trap rules to add/delete
func (c *iptablesSupervisor) trapRules(appChain string, netChain string, network string) [][]string {

	trapRules := [][]string{
		// Application Syn and Syn/Ack
		{
			triremeAppPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "NFQUEUE", "--queue-balance", c.applicationQueues,
		},

		// Application everything else
		{
			triremeAppAckPacketIPTableContext, appChain,
			"-d", network,
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", c.applicationQueues,
		},

		// Network side rules
		{
			triremeNetPacketIPTableContext, netChain,
			"-s", network,
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", c.networkQueues,
		},
	}

	return trapRules
}

// addPacketTrap adds the necessary iptables rules to capture control packets to user space
func (c *iptablesSupervisor) addPacketTrap(appChain string, netChain string, ip string) error {

	for _, network := range c.targetNetworks {

		trapRules := c.trapRules(appChain, netChain, network)
		for _, tr := range trapRules {

			if err := c.ipt.Append(tr[0], tr[1], tr[2:]...); err != nil {
				glog.V(2).Infoln("Failed to create "+tr[0]+":"+tr[1]+" rule that redirects to container chain", err)
				return err
			}
		}
	}

	return nil
}

// deletePacketTrap deletes the iptables rules that trap control  packets to user space
func (c *iptablesSupervisor) deletePacketTrap(appChain, netChain, ip string) error {

	for _, network := range c.targetNetworks {

		trapRules := c.trapRules(appChain, netChain, network)
		for _, tr := range trapRules {

			if err := c.ipt.Append(tr[0], tr[1], tr[2:]...); err != nil {
				glog.V(2).Infoln("Failed to delete "+tr[0]+":"+tr[1]+" rule that redirects to container chain", err)
				return err
			}
		}
	}

	return nil
}

// addAppACLs adds a set of rules to the external services that are initiated
// by an application. The allow rules are inserted with highest priority.
func (c *iptablesSupervisor) addAppACLs(chain string, ip string, rules []policy.IPRule) error {

	for i := range rules {

		if err := c.ipt.Insert(
			triremeAppPacketIPTableContext, chain, 1,
			"-p", rules[i].Protocol,
			"-d", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			glog.V(2).Infoln("Error adding rule ", rules[i], err)
			return err
		}

	}

	if err := c.ipt.Append(
		triremeAppPacketIPTableContext, chain,
		"-d", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP"); err != nil {
		glog.V(2).Infoln("Error adding default rule ! ", err)
		return err
	}

	return nil
}

// deleteAppACLs deletes the rules associated with traffic to external services
func (c *iptablesSupervisor) deleteAppACLs(chain string, ip string, rules []policy.IPRule) error {

	for i := range rules {
		if err := c.ipt.Delete(
			triremeAppPacketIPTableContext, chain,
			"-p", rules[i].Protocol,
			"-d", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			glog.V(2).Infoln("Error removing ingress ACL rule ", rules[i], err)
		}
	}

	if err := c.ipt.Delete(
		triremeAppPacketIPTableContext, chain,
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
func (c *iptablesSupervisor) addNetACLs(chain, ip string, rules []policy.IPRule) error {

	for i := range rules {

		if err := c.ipt.Insert(
			triremeNetPacketIPTableContext, chain, 1,
			"-p", rules[i].Protocol,
			"-s", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			glog.V(2).Infoln("Error adding rule ", rules[i], err)
			return err
		}

	}

	if err := c.ipt.Append(
		triremeNetPacketIPTableContext, chain,
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
func (c *iptablesSupervisor) deleteNetACLs(chain string, ip string, rules []policy.IPRule) error {

	for i := range rules {
		if err := c.ipt.Delete(
			triremeNetPacketIPTableContext, chain,
			"-p", rules[i].Protocol,
			"-s", rules[i].Address,
			"--dport", rules[i].Port,
			"-j", "ACCEPT",
		); err != nil {
			glog.V(2).Infoln("Error removing egress ACL rule ", rules[i], err)
		}
	}

	if err := c.ipt.Delete(
		triremeNetPacketIPTableContext, chain,
		"-s", "0.0.0.0/0",
		"-p", "tcp", "-m", "state", "--state", "NEW",
		"-j", "DROP",
	); err != nil {
		glog.V(2).Infoln("Error removing default ACL rule  ! ", err)
	}

	return nil
}

func (c *iptablesSupervisor) cleanACLSection(context, section, chainPrefix string) {

	if err := c.ipt.ClearChain(context, section); err != nil {
		glog.V(2).Infoln("Can't clear ", section, " iptables command")
		return
	}

	rules, err := c.ipt.ListChains(context)
	if err != nil {
		glog.V(5).Infoln("No chain rules found")
		return
	}

	for _, rule := range rules {

		if strings.Contains(rule, chainPrefix) {
			c.ipt.ClearChain(context, rule)
			c.ipt.DeleteChain(context, rule)
		}
	}
}

func add(a, b interface{}) interface{} {
	entry := a.(*supervisorCacheEntry)
	entry.index += b.(int)
	return entry
}
