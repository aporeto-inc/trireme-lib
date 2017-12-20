package pucontext

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/acls"
	"github.com/aporeto-inc/trireme-lib/enforcer/lookup"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

type policies struct {
	observeRejectRules *lookup.PolicyDB // Packet: Continue       Report:    Drop
	rejectRules        *lookup.PolicyDB // Packet:     Drop       Report:    Drop
	observeAcceptRules *lookup.PolicyDB // Packet: Continue       Report: Forward
	acceptRules        *lookup.PolicyDB // Packet:  Forward       Report: Forward
	observeApplyRules  *lookup.PolicyDB // Packet:  Forward       Report: Forward
}

// PUContext holds data indexed by the PU ID
type PUContext struct {
	id                string
	managementID      string
	identity          *policy.TagStore
	annotations       *policy.TagStore
	txt               *policies
	rcv               *policies
	applicationACLs   *acls.ACLCache
	networkACLs       *acls.ACLCache
	externalIPCache   cache.DataStore
	Extension         interface{}
	ip                string
	mark              string
	ProxyPort         string
	ports             []string
	puType            constants.PUType
	synToken          []byte
	synServiceContext []byte
	synExpiration     time.Time
	sync.RWMutex
}

// NewPU creates a new PU context
func NewPU(contextID string, puInfo *policy.PUInfo, timeout time.Duration) (*PUContext, error) {

	ip, ok := puInfo.Runtime.DefaultIPAddress()
	if !ok {
		ip = "0.0.0.0/0"
	}

	pu := &PUContext{
		id:              contextID,
		managementID:    puInfo.Policy.ManagementID(),
		puType:          puInfo.Runtime.PUType(),
		ip:              ip,
		identity:        puInfo.Policy.Identity(),
		annotations:     puInfo.Policy.Annotations(),
		externalIPCache: cache.NewCacheWithExpiration("External IP Cache", timeout),
		applicationACLs: acls.NewACLCache(),
		networkACLs:     acls.NewACLCache(),
		mark:            puInfo.Runtime.Options().CgroupMark,
	}

	pu.CreateRcvRules(puInfo.Policy.ReceiverRules())

	pu.CreateTxtRules(puInfo.Policy.TransmitterRules())

	ports := policy.ConvertServicesToPortList(puInfo.Runtime.Options().Services)
	pu.ports = strings.Split(ports, ",")

	if err := pu.applicationACLs.AddRuleList(puInfo.Policy.ApplicationACLs()); err != nil {
		return nil, err
	}

	if err := pu.networkACLs.AddRuleList(puInfo.Policy.NetworkACLs()); err != nil {
		return nil, err
	}

	return pu, nil

}

// ID returns the ID of the PU
func (p *PUContext) ID() string {
	return p.id
}

// ManagementID returns the management ID
func (p *PUContext) ManagementID() string {
	return p.managementID
}

// Type return the pu type
func (p *PUContext) Type() constants.PUType {
	return p.puType
}

// Identity returns the indentity
func (p *PUContext) Identity() *policy.TagStore {
	return p.identity
}

// IP returns the IP of the PU
func (p *PUContext) IP() string {
	return p.ip
}

// Mark returns the PU mark
func (p *PUContext) Mark() string {
	return p.mark
}

// Ports returns the PU ports
func (p *PUContext) Ports() []string {
	return p.ports
}

// Annotations returns the annotations
func (p *PUContext) Annotations() *policy.TagStore {
	return p.annotations
}

// RetrieveCachedExternalFlowPolicy returns the policy for an external IP
func (p *PUContext) RetrieveCachedExternalFlowPolicy(id string) (interface{}, error) {
	return p.externalIPCache.Get(id)
}

// NetworkACLPolicy retrieves the policy based on ACLs
func (p *PUContext) NetworkACLPolicy(packet *packet.Packet) (*policy.FlowPolicy, error) {
	return p.networkACLs.GetMatchingAction(packet.SourceAddress.To4(), packet.DestinationPort)
}

// ApplicationACLPolicy retrieves the policy based on ACLs
func (p *PUContext) ApplicationACLPolicy(packet *packet.Packet) (*policy.FlowPolicy, error) {
	return p.applicationACLs.GetMatchingAction(packet.SourceAddress.To4(), packet.SourcePort)
}

// CacheExternalFlowPolicy will cache an external flow
func (p *PUContext) CacheExternalFlowPolicy(packet *packet.Packet, plc interface{}) {
	p.externalIPCache.AddOrUpdate(packet.SourceAddress.String()+":"+strconv.Itoa(int(packet.SourcePort)), plc)
}

// GetProcessKeys returns the cache keys for a process
func (p *PUContext) GetProcessKeys() (string, []string) {
	return p.mark, p.ports
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

// GetCachedToken returns the cached syn packet token
func (p *PUContext) GetCachedToken() ([]byte, error) {

	p.RLock()
	defer p.RUnlock()

	if p.synExpiration.After(time.Now()) && len(p.synToken) > 0 {
		return p.synToken, nil
	}

	return nil, fmt.Errorf("eiixpired Token")
}

// UpdateCachedToken updates the local cached token
func (p *PUContext) UpdateCachedToken(token []byte) {

	p.Lock()

	p.synToken = token
	p.synExpiration = time.Now().Add(time.Millisecond * 500)

	p.Unlock()

}

// createRuleDBs creates the database of rules from the policy
func (p *PUContext) createRuleDBs(policyRules policy.TagSelectorList) *policies {

	policyDB := &policies{
		rejectRules:        lookup.NewPolicyDB(),
		observeRejectRules: lookup.NewPolicyDB(),
		acceptRules:        lookup.NewPolicyDB(),
		observeAcceptRules: lookup.NewPolicyDB(),
		observeApplyRules:  lookup.NewPolicyDB(),
	}

	for _, rule := range policyRules {
		if rule.Policy.ObserveAction.ObserveContinue() {
			if rule.Policy.Action.Accepted() {
				zap.L().Info("Observed Accept with Continue:", zap.Reflect("rule", rule))
				policyDB.observeAcceptRules.AddPolicy(rule)
			} else if rule.Policy.Action.Rejected() {
				zap.L().Info("Observed Reject with Continue:", zap.Reflect("rule", rule))
				policyDB.observeRejectRules.AddPolicy(rule)
			}
		} else if rule.Policy.ObserveAction.ObserveApply() {
			zap.L().Info("Observed with Apply:", zap.Reflect("rule", rule))
			policyDB.observeApplyRules.AddPolicy(rule)
		} else if rule.Policy.Action.Accepted() {
			zap.L().Info("Accept:", zap.Reflect("rule", rule))
			policyDB.acceptRules.AddPolicy(rule)
		} else if rule.Policy.Action.Rejected() {
			zap.L().Info("Reject:", zap.Reflect("rule", rule))
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

	zap.L().Info("Tags", zap.String("tags", tags.String()))
	if !skipRejectPolicies {
		// Look for rejection rules
		observeIndex, observeAction := policies.observeRejectRules.Search(tags)
		if observeIndex >= 0 {
			reportingAction = observeAction.(*policy.FlowPolicy)
			zap.L().Info("Report observe reject with continue:", zap.Reflect("action", reportingAction))
		}

		if packetAction == nil {
			index, action := policies.rejectRules.Search(tags)
			if index >= 0 {
				packetAction = action.(*policy.FlowPolicy)
				zap.L().Info("Packet reject:", zap.Reflect("action", packetAction))
				if reportingAction == nil {
					reportingAction = packetAction
				}
				return reportingAction, packetAction
			}
		}
	}

	if reportingAction == nil {
		// Look for allow rules
		observeIndex, observeAction := policies.observeAcceptRules.Search(tags)
		if observeIndex >= 0 {
			reportingAction = observeAction.(*policy.FlowPolicy)
			zap.L().Info("Report observe accept with continue:", zap.Reflect("action", reportingAction))
		}
	}

	if packetAction == nil {
		index, action := policies.acceptRules.Search(tags)
		if index >= 0 {
			packetAction = action.(*policy.FlowPolicy)
			zap.L().Info("Packet reject:", zap.Reflect("action", packetAction))
			if reportingAction == nil {
				reportingAction = packetAction
			}
			return reportingAction, packetAction
		}
	}

	// Look for observe apply rules
	observeIndex, observeAction := policies.observeApplyRules.Search(tags)
	if observeIndex >= 0 {
		packetAction = observeAction.(*policy.FlowPolicy)
		zap.L().Info("Packet apply:", zap.Reflect("action", packetAction))
		if reportingAction == nil {
			reportingAction = packetAction
			zap.L().Info("Report apply:", zap.Reflect("action", packetAction))
		}
		return reportingAction, packetAction
	}

	// Handle default if nothing provides to drop with no policyID.
	if packetAction == nil {
		packetAction = &policy.FlowPolicy{
			Action:   policy.Reject,
			PolicyID: "",
		}
		zap.L().Info("Packet default reject:", zap.Reflect("action", packetAction))
	}

	if reportingAction == nil {
		reportingAction = packetAction
		zap.L().Info("Report default reject:", zap.Reflect("action", packetAction))
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
