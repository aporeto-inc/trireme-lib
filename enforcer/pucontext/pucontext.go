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

// PUContext holds data indexed by the PU ID
type PUContext struct {
	id                string
	managementID      string
	identity          *policy.TagStore
	annotations       *policy.TagStore
	acceptTxRules     *lookup.PolicyDB
	rejectTxRules     *lookup.PolicyDB
	acceptRcvRules    *lookup.PolicyDB
	rejectRcvRules    *lookup.PolicyDB
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

// PrintPolicy prints policy
func (p *PUContext) PrintPolicy() {
	zap.L().Info("Accept Rcv Rules")
	p.acceptRcvRules.PrintPolicyDB()

	zap.L().Info("Reject rcv Rules")
	p.rejectRcvRules.PrintPolicyDB()

	zap.L().Info("Accept Tx Rules")
	p.acceptTxRules.PrintPolicyDB()

	zap.L().Info("Reject Tx rules")
	p.rejectTxRules.PrintPolicyDB()
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

// SearchAcceptTxRules returns the accept Tx Rules
func (p *PUContext) SearchAcceptTxRules(claims *policy.TagStore) (int, interface{}) {
	return p.acceptTxRules.Search(claims)
}

// SearchRejectTxRules searches the reject rules for a policy match
func (p *PUContext) SearchRejectTxRules(claims *policy.TagStore) (int, interface{}) {
	return p.rejectTxRules.Search(claims)
}

// SearchAcceptRcvRules searches the accept rules for a policy match
func (p *PUContext) SearchAcceptRcvRules(claims *policy.TagStore) (int, interface{}) {
	return p.acceptRcvRules.Search(claims)
}

// SearchRejectRcvRules returns the reject receive rules
func (p *PUContext) SearchRejectRcvRules(claims *policy.TagStore) (int, interface{}) {
	return p.rejectRcvRules.Search(claims)
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
	return p.synServiceContext
}

// UpdateSynServiceContext updates the synServiceContext
func (p *PUContext) UpdateSynServiceContext(synServiceContext []byte) {

	p.Lock()
	defer p.Unlock()

	p.synServiceContext = synServiceContext
}

// GetCachedToken returns the cached syn packet token
func (p *PUContext) GetCachedToken() ([]byte, error) {

	p.RLock()
	defer p.RUnlock()

	if p.synExpiration.After(time.Now()) && len(p.synToken) > 0 {
		return p.synToken, nil
	}

	return nil, fmt.Errorf("Expired Token")
}

// UpdateCachedToken updates the local cached token
func (p *PUContext) UpdateCachedToken(token []byte) {

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
