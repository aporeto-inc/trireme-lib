package pucontext

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/acls"
	"github.com/aporeto-inc/trireme/enforcer/lookup"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/policy"
)

// PU includes all the context of a PU. All values are private and
// they can only be written during creation, other than the syn token
// This guarantees that we have lock free operations
type PU struct {
	id              string
	managementID    string
	identity        *policy.TagStore
	annotations     *policy.TagStore
	acceptTxRules   *lookup.PolicyDB
	rejectTxRules   *lookup.PolicyDB
	acceptRcvRules  *lookup.PolicyDB
	rejectRcvRules  *lookup.PolicyDB
	applicationACLs *acls.ACLCache
	networkACLs     *acls.ACLCache
	externalIPCache cache.DataStore
	ip              string
	mark            string
	ports           []string
	puType          constants.PUType
	synToken        []byte
	synExpiration   time.Time
	sync.RWMutex
}

// NewPU creates a new PU context
func NewPU(contextID string, puInfo *policy.PUInfo, timeout time.Duration) (*PU, error) {

	ip, ok := puInfo.Runtime.DefaultIPAddress()
	if !ok {
		ip = "0.0.0.0/0"
	}

	pu := &PU{
		id:              contextID,
		managementID:    puInfo.Policy.ManagementID(),
		puType:          puInfo.Runtime.PUType(),
		ip:              ip,
		identity:        puInfo.Policy.Identity(),
		annotations:     puInfo.Policy.Annotations(),
		externalIPCache: cache.NewCacheWithExpiration(timeout),
		applicationACLs: acls.NewACLCache(),
		networkACLs:     acls.NewACLCache(),
		mark:            puInfo.Runtime.Options().CgroupMark,
	}

	pu.acceptRcvRules, pu.rejectRcvRules = createRuleDBs(puInfo.Policy.ReceiverRules())

	pu.acceptTxRules, pu.rejectTxRules = createRuleDBs(puInfo.Policy.TransmitterRules())

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
func (p *PU) ID() string {
	return p.id
}

// ManagementID returns the management ID
func (p *PU) ManagementID() string {
	return p.managementID
}

// Type return the pu type
func (p *PU) Type() constants.PUType {
	return p.puType
}

// Identity returns the indentity
func (p *PU) Identity() *policy.TagStore {
	return p.identity
}

// IP returns the IP of the PU
func (p *PU) IP() string {
	return p.ip
}

// Mark returns the PU mark
func (p *PU) Mark() string {
	return p.mark
}

// Ports returns the PU ports
func (p *PU) Ports() []string {
	return p.ports
}

// Annotations returns the annotations
func (p *PU) Annotations() *policy.TagStore {
	return p.annotations
}

// SearchAcceptTxRules returns the accept Tx Rules
func (p *PU) SearchAcceptTxRules(claims *policy.TagStore) (int, interface{}) {
	return p.acceptTxRules.Search(claims)
}

// SearchRejectTxRules searches the reject rules for a policy match
func (p *PU) SearchRejectTxRules(claims *policy.TagStore) (int, interface{}) {
	return p.rejectTxRules.Search(claims)
}

// SearchAcceptRcvRules searches the accept rules for a policy match
func (p *PU) SearchAcceptRcvRules(claims *policy.TagStore) (int, interface{}) {
	return p.acceptRcvRules.Search(claims)
}

// SearchRejectRcvRules returns the reject receive rules
func (p *PU) SearchRejectRcvRules(claims *policy.TagStore) (int, interface{}) {
	return p.rejectRcvRules.Search(claims)
}

// RetrieveCachedExternalFlowPolicy returns the policy for an external IP
func (p *PU) RetrieveCachedExternalFlowPolicy(id string) (interface{}, error) {
	return p.externalIPCache.Get(id)
}

// NetworkACLPolicy retrieves the policy based on ACLs
func (p *PU) NetworkACLPolicy(packet *packet.Packet) (*policy.FlowPolicy, error) {
	return p.networkACLs.GetMatchingAction(packet.SourceAddress.To4(), packet.DestinationPort)
}

// ApplicationACLPolicy retrieves the policy based on ACLs
func (p *PU) ApplicationACLPolicy(packet *packet.Packet) (*policy.FlowPolicy, error) {
	return p.applicationACLs.GetMatchingAction(packet.SourceAddress.To4(), packet.SourcePort)
}

// CacheExternalFlowPolicy will cache an external flow
func (p *PU) CacheExternalFlowPolicy(packet *packet.Packet, plc interface{}) {
	p.externalIPCache.AddOrUpdate(packet.SourceAddress.String()+":"+strconv.Itoa(int(packet.SourcePort)), plc)
}

// GetProcessKeys returns the cache keys for a process
func (p *PU) GetProcessKeys() (string, []string) {
	return p.mark, p.ports
}

// GetCachedToken returns the cached syn packet token
func (p *PU) GetCachedToken() ([]byte, error) {
	p.RLock()
	defer p.RUnlock()
	if p.synExpiration.After(time.Now()) && len(p.synToken) > 0 {
		return p.synToken, nil
	}

	return nil, fmt.Errorf("Expired Token")
}

// UpdateCachedToken updates the local cached token
func (p *PU) UpdateCachedToken(token []byte) {
	p.Lock()
	defer p.Unlock()

	p.synToken = token
	p.synExpiration = time.Now().Add(time.Millisecond * 500)
}

// createRuleDBs creates the database of rules from the policy
func createRuleDBs(policyRules policy.TagSelectorList) (*lookup.PolicyDB, *lookup.PolicyDB) {

	acceptRules := lookup.NewPolicyDB()
	rejectRules := lookup.NewPolicyDB()

	for _, rule := range policyRules {
		if rule.Policy.Action&policy.Accept != 0 {
			acceptRules.AddPolicy(rule)
		} else if rule.Policy.Action&policy.Reject != 0 {
			rejectRules.AddPolicy(rule)
		} else {
			continue
		}
	}
	return acceptRules, rejectRules
}
