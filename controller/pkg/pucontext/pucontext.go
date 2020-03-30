package pucontext

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio/pkg/wildcard"
	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/controller/constants"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/acls"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/lookup"

	"go.aporeto.io/trireme-lib/v11/controller/pkg/counters"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/v11/policy"
	"go.aporeto.io/trireme-lib/v11/utils/cache"
)

type policies struct {
	observeRejectRules *lookup.PolicyDB // Packet: Continue       Report:    Drop
	rejectRules        *lookup.PolicyDB // Packet:     Drop       Report:    Drop
	observeAcceptRules *lookup.PolicyDB // Packet: Continue       Report: Forward
	acceptRules        *lookup.PolicyDB // Packet:  Forward       Report: Forward
	observeApplyRules  *lookup.PolicyDB // Packet:  Forward       Report: Forward
	encryptRules       *lookup.PolicyDB // Packet: Encrypt       Report: Encrypt
}

// PUContext holds data indexed by the PU ID
type PUContext struct {
	id                  string
	hashID              string
	username            string
	autoport            bool
	managementID        string
	managementNamespace string
	identity            *policy.TagStore
	annotations         *policy.TagStore
	compressedTags      *policy.TagStore
	txt                 *policies
	rcv                 *policies
	ApplicationACLs     *acls.ACLCache
	networkACLs         *acls.ACLCache
	externalIPCache     cache.DataStore
	DNSACLs             policy.DNSRuleList
	DNSProxyPort        string
	mark                string
	tcpPorts            []string
	udpPorts            []string
	puType              common.PUType
	synToken            []byte
	synServiceContext   []byte
	synExpiration       time.Time
	jwt                 string
	jwtExpiration       time.Time
	scopes              []string
	Extension           interface{}
	counters            *counters.Counters

	sync.RWMutex
}

// NewPU creates a new PU context
func NewPU(contextID string, puInfo *policy.PUInfo, timeout time.Duration) (*PUContext, error) {

	hashID, err := policy.Fnv32Hash(contextID)
	if err != nil {
		return nil, fmt.Errorf("unable to hash contextID: %v", err)
	}

	pu := &PUContext{
		id:                  contextID,
		hashID:              hashID,
		username:            puInfo.Runtime.Options().UserID,
		autoport:            puInfo.Runtime.Options().AutoPort,
		managementID:        puInfo.Policy.ManagementID(),
		managementNamespace: puInfo.Policy.ManagementNamespace(),
		puType:              puInfo.Runtime.PUType(),
		identity:            puInfo.Policy.Identity(),
		annotations:         puInfo.Policy.Annotations(),
		compressedTags:      puInfo.Policy.CompressedTags(),
		externalIPCache:     cache.NewCacheWithExpiration("External IP Cache", timeout),
		ApplicationACLs:     acls.NewACLCache(),
		networkACLs:         acls.NewACLCache(),
		DNSACLs:             puInfo.Policy.DNSNameACLs(),
		mark:                puInfo.Runtime.Options().CgroupMark,
		scopes:              puInfo.Policy.Scopes(),
		counters:            counters.NewCounters(),
	}

	pu.CreateRcvRules(puInfo.Policy.ReceiverRules())

	pu.CreateTxtRules(puInfo.Policy.TransmitterRules())

	tcpPorts, udpPorts := common.ConvertServicesToProtocolPortList(puInfo.Runtime.Options().Services)
	pu.tcpPorts = strings.Split(tcpPorts, ",")
	pu.udpPorts = strings.Split(udpPorts, ",")

	if err := pu.UpdateApplicationACLs(puInfo.Policy.ApplicationACLs()); err != nil {
		return nil, err
	}

	if err := pu.UpdateNetworkACLs(puInfo.Policy.NetworkACLs()); err != nil {
		return nil, err
	}

	return pu, nil
}

// GetPolicyFromFQDN gets the list of policies that are mapped with the hostname
func (p *PUContext) GetPolicyFromFQDN(fqdn string) ([]policy.PortProtocolPolicy, error) {
	p.RLock()
	defer p.RUnlock()

	// If we find a direct match, return policy
	if v, ok := p.DNSACLs[fqdn]; ok {
		return v, nil
	}

	// Try if there is a wildcard match
	for policyName, policy := range p.DNSACLs {
		if wildcard.MatchSimple(policyName, fqdn) {
			return policy, nil
		}
	}

	return nil, fmt.Errorf("Policy doesn't exist")
}

// ID returns the ID of the PU
func (p *PUContext) ID() string {
	return p.id
}

// HashID returns the hash of the ID of the PU
func (p *PUContext) HashID() string {
	return p.hashID
}

// Username returns the ID of the PU
func (p *PUContext) Username() string {
	return p.username
}

// Autoport returns if auto port feature is set on the PU
func (p *PUContext) Autoport() bool {
	return p.autoport
}

// ManagementID returns the management ID
func (p *PUContext) ManagementID() string {
	return p.managementID
}

// ManagementNamespace returns the management namespace
func (p *PUContext) ManagementNamespace() string {
	return p.managementNamespace
}

// Type return the pu type
func (p *PUContext) Type() common.PUType {
	return p.puType
}

// Identity returns the indentity
func (p *PUContext) Identity() *policy.TagStore {
	return p.identity
}

// Mark returns the PU mark
func (p *PUContext) Mark() string {
	return p.mark
}

// TCPPorts returns the PU TCP ports
func (p *PUContext) TCPPorts() []string {
	return p.tcpPorts
}

// UDPPorts returns the PU UDP ports
func (p *PUContext) UDPPorts() []string {
	return p.udpPorts
}

// Annotations returns the annotations
func (p *PUContext) Annotations() *policy.TagStore {
	return p.annotations
}

// CompressedTags returns the compressed tags.
func (p *PUContext) CompressedTags() *policy.TagStore {
	return p.compressedTags
}

// RetrieveCachedExternalFlowPolicy returns the policy for an external IP
func (p *PUContext) RetrieveCachedExternalFlowPolicy(id string) (interface{}, error) {
	return p.externalIPCache.Get(id)
}

// NetworkACLPolicy retrieves the policy based on ACLs
func (p *PUContext) NetworkACLPolicy(packet *packet.Packet) (report *policy.FlowPolicy, action *policy.FlowPolicy, err error) {
	defer p.RUnlock()
	p.RLock()

	return p.networkACLs.GetMatchingAction(packet.SourceAddress(), packet.DestPort())
}

// NetworkACLPolicyFromAddr retrieve the policy given an address and port.
func (p *PUContext) NetworkACLPolicyFromAddr(addr net.IP, port uint16) (report *policy.FlowPolicy, action *policy.FlowPolicy, err error) {
	defer p.RUnlock()
	p.RLock()

	return p.networkACLs.GetMatchingAction(addr, port)
}

// ApplicationACLPolicyFromAddr retrieve the policy given an address and port.
func (p *PUContext) ApplicationACLPolicyFromAddr(addr net.IP, port uint16) (report *policy.FlowPolicy, action *policy.FlowPolicy, err error) {
	defer p.RUnlock()
	p.RLock()
	return p.ApplicationACLs.GetMatchingAction(addr, port)
}

// UpdateApplicationACLs updates the application ACL policy
func (p *PUContext) UpdateApplicationACLs(rules policy.IPRuleList) error {
	defer p.Unlock()
	p.Lock()
	return p.ApplicationACLs.AddRuleList(rules)
}

// RemoveApplicationACL removes the application ACLs which are indexed with (ip, mask) key
func (p *PUContext) RemoveApplicationACL(addr net.IP, mask int) {
	defer p.Unlock()
	p.Lock()
	p.ApplicationACLs.RemoveIPMask(addr, mask)
}

// UpdateNetworkACLs updates the network ACL policy
func (p *PUContext) UpdateNetworkACLs(rules policy.IPRuleList) error {
	defer p.Unlock()
	p.Lock()
	return p.networkACLs.AddRuleList(rules)
}

// CacheExternalFlowPolicy will cache an external flow
func (p *PUContext) CacheExternalFlowPolicy(packet *packet.Packet, plc interface{}) {
	p.externalIPCache.AddOrUpdate(packet.SourceAddress().String()+":"+strconv.Itoa(int(packet.SourcePort())), plc)
}

// GetProcessKeys returns the cache keys for a process
func (p *PUContext) GetProcessKeys() (string, []string, []string) {
	return p.mark, p.tcpPorts, p.udpPorts
}

// SynServiceContext returns synServiceContext
func (p *PUContext) SynServiceContext() []byte {
	p.RLock()
	defer p.RUnlock()
	return p.synServiceContext
}

// UpdateSynServiceContext updates the synServiceContext
func (p *PUContext) UpdateSynServiceContext(synServiceContext []byte) {

	p.Lock()
	p.synServiceContext = synServiceContext
	p.Unlock()
}

// GetCachedTokenAndServiceContext returns the cached syn packet token
func (p *PUContext) GetCachedTokenAndServiceContext() ([]byte, []byte, error) {

	p.RLock()
	defer p.RUnlock()

	if p.synExpiration.After(time.Now()) && len(p.synToken) > 0 {
		token := make([]byte, len(p.synToken))
		copy(token, p.synToken)
		return token, p.synServiceContext, nil
	}

	return nil, nil, fmt.Errorf("expired Token")
}

// UpdateCachedTokenAndServiceContext updates the local cached token
func (p *PUContext) UpdateCachedTokenAndServiceContext(token []byte, serviceContext []byte) {

	p.Lock()

	p.synToken = token
	p.synExpiration = time.Now().Add(constants.SynTokenCacheValiditity)
	p.synServiceContext = serviceContext

	p.Unlock()

}

// Scopes returns the scopes.
func (p *PUContext) Scopes() []string {
	p.RLock()
	defer p.RUnlock()

	return p.scopes
}

// Counters returns the scopes.
func (p *PUContext) Counters() *counters.Counters {
	p.RLock()
	defer p.RUnlock()

	return p.counters
}

// GetJWT retrieves the JWT if it exists in the cache. Returns error otherwise.
func (p *PUContext) GetJWT() (string, error) {
	p.RLock()
	defer p.RUnlock()

	if p.jwtExpiration.After(time.Now()) && len(p.jwt) > 0 {
		return p.jwt, nil
	}

	return "", fmt.Errorf("expired token")
}

// UpdateJWT updates the JWT and provides a new expiration date.
func (p *PUContext) UpdateJWT(jwt string, expiration time.Time) {
	p.Lock()
	defer p.Unlock()

	p.jwt = jwt
	p.jwtExpiration = expiration
}

// createRuleDBs creates the database of rules from the policy
func (p *PUContext) createRuleDBs(policyRules policy.TagSelectorList) *policies {

	policyDB := &policies{
		rejectRules:        lookup.NewPolicyDB(),
		observeRejectRules: lookup.NewPolicyDB(),
		acceptRules:        lookup.NewPolicyDB(),
		observeAcceptRules: lookup.NewPolicyDB(),
		observeApplyRules:  lookup.NewPolicyDB(),
		encryptRules:       lookup.NewPolicyDB(),
	}

	for _, rule := range policyRules {
		// Add encrypt rule to encrypt table.
		if rule.Policy.Action.Encrypted() {
			policyDB.encryptRules.AddPolicy(rule)
		}

		if rule.Policy.ObserveAction.ObserveContinue() {
			if rule.Policy.Action.Accepted() {
				policyDB.observeAcceptRules.AddPolicy(rule)
			} else if rule.Policy.Action.Rejected() {
				policyDB.observeRejectRules.AddPolicy(rule)
			}
		} else if rule.Policy.ObserveAction.ObserveApply() {
			policyDB.observeApplyRules.AddPolicy(rule)
		} else if rule.Policy.Action.Accepted() {
			policyDB.acceptRules.AddPolicy(rule)
		} else if rule.Policy.Action.Rejected() {
			policyDB.rejectRules.AddPolicy(rule)
		} else {
			continue
		}
	}
	return policyDB
}

// CreateRcvRules create receive rules for this PU based on the update of the policy.
func (p *PUContext) CreateRcvRules(policyRules policy.TagSelectorList) {
	p.rcv = p.createRuleDBs(policyRules)
}

// CreateTxtRules create receive rules for this PU based on the update of the policy.
func (p *PUContext) CreateTxtRules(policyRules policy.TagSelectorList) {
	p.txt = p.createRuleDBs(policyRules)
}

// searchRules searches all reject, accpet and observed rules and returns reporting and packet forwarding action
func (p *PUContext) searchRules(
	policies *policies,
	tags *policy.TagStore,
	skipRejectPolicies bool,
) (report *policy.FlowPolicy, packet *policy.FlowPolicy) {

	var reportingAction *policy.FlowPolicy
	var packetAction *policy.FlowPolicy

	if !skipRejectPolicies {
		// Look for rejection rules
		observeIndex, observeAction := policies.observeRejectRules.Search(tags)
		if observeIndex >= 0 {
			reportingAction = observeAction.(*policy.FlowPolicy)
		}

		index, action := policies.rejectRules.Search(tags)
		if index >= 0 {
			packetAction = action.(*policy.FlowPolicy)
			if reportingAction == nil {
				reportingAction = packetAction
			}
			return reportingAction, packetAction
		}
	}

	if reportingAction == nil {
		// Look for allow rules
		observeIndex, observeAction := policies.observeAcceptRules.Search(tags)
		if observeIndex >= 0 {
			reportingAction = observeAction.(*policy.FlowPolicy)
		}
	}

	index, action := policies.acceptRules.Search(tags)
	if index >= 0 {
		packetAction = action.(*policy.FlowPolicy)
		// Look for encrypt rules
		encryptIndex, _ := policies.encryptRules.Search(tags)
		if encryptIndex >= 0 {
			// Do not overwrite the action for accept rules.
			finalAction := action.(*policy.FlowPolicy)
			packetAction = &policy.FlowPolicy{
				Action:    policy.Accept | policy.Encrypt,
				PolicyID:  finalAction.PolicyID,
				ServiceID: finalAction.ServiceID,
			}
		}
		if reportingAction == nil {
			reportingAction = packetAction
		}
		return reportingAction, packetAction
	}

	// Look for observe apply rules
	observeIndex, observeAction := policies.observeApplyRules.Search(tags)
	if observeIndex >= 0 {
		packetAction = observeAction.(*policy.FlowPolicy)
		if reportingAction == nil {
			reportingAction = packetAction
		}
		return reportingAction, packetAction
	}

	// Handle default if nothing provides to drop with no policyID.
	packetAction = &policy.FlowPolicy{
		Action:   policy.Reject,
		PolicyID: "default",
	}

	if reportingAction == nil {
		reportingAction = packetAction
	}

	return reportingAction, packetAction
}

// SearchTxtRules searches both receive and observed transmit rules and returns the index and action
func (p *PUContext) SearchTxtRules(
	tags *policy.TagStore,
	skipRejectPolicies bool,
) (report *policy.FlowPolicy, packet *policy.FlowPolicy) {
	return p.searchRules(p.txt, tags, skipRejectPolicies)
}

// SearchRcvRules searches both receive and observed receive rules and returns the index and action
func (p *PUContext) SearchRcvRules(
	tags *policy.TagStore,
) (report *policy.FlowPolicy, packet *policy.FlowPolicy) {
	return p.searchRules(p.rcv, tags, false)
}
