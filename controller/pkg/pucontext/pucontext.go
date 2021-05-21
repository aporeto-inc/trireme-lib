package pucontext

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio/pkg/wildcard"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/acls"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/lookup"
	"go.aporeto.io/underwater/core/tagutils"
	"go.uber.org/zap"

	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/ephemeralkeys"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/tokens"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.aporeto.io/enforcerd/trireme-lib/utils/crypto"
)

type policies struct {
	observeRejectRules *lookup.PolicyDB // Packet: Continue       Report:    Drop
	rejectRules        *lookup.PolicyDB // Packet:     Drop       Report:    Drop
	observeAcceptRules *lookup.PolicyDB // Packet: Continue       Report: Forward
	acceptRules        *lookup.PolicyDB // Packet:  Forward       Report: Forward
	observeApplyRules  *lookup.PolicyDB // Packet:  Forward       Report: Forward
	encryptRules       *lookup.PolicyDB // Packet: Encrypt       Report: Encrypt
}

type synTokenInfo struct {
	datapathSecret  secrets.Secrets
	privateKey      *ephemeralkeys.PrivateKey
	publicKeyV1     []byte
	publicKeySignV1 []byte
	publicKeyV2     []byte
	publicKeySignV2 []byte
	token           []byte
}

// PUContext holds data indexed by the PU ID
type PUContext struct {
	id                      string
	hashID                  string
	username                string
	autoport                bool
	managementID            string
	managementNamespace     string
	managementNamespaceHash string
	identity                *policy.TagStore
	annotations             *policy.TagStore
	compressedTags          *policy.TagStore
	txt                     *policies
	rcv                     *policies
	ApplicationACLs         *acls.ACLCache
	networkACLs             *acls.ACLCache
	externalIPCache         cache.DataStore
	DNSACLs                 policy.DNSRuleList
	DNSProxyPort            string
	mark                    string
	tcpPorts                []string
	udpPorts                []string
	puType                  common.PUType
	jwt                     string
	jwtExpiration           time.Time
	scopes                  []string
	Extension               interface{}
	counters                *counters.Counters
	puInfo                  *policy.PUInfo
	synToken                *synTokenInfo
	ctxCancel               context.CancelFunc
	tokenAccessor           tokenaccessor.TokenAccessor
	appDefaultFlowPolicy    *policy.FlowPolicy
	netDefaultFlowPolicy    *policy.FlowPolicy
	sync.RWMutex
}

// NewPU creates a new PU context
func NewPU(contextID string, puInfo *policy.PUInfo, tokenAccessor tokenaccessor.TokenAccessor, timeout time.Duration) (*PUContext, error) {

	hashID, err := policy.Fnv32Hash(contextID)
	if err != nil {
		return nil, fmt.Errorf("unable to hash contextID: %v", err)
	}

	pu := &PUContext{
		id:                   contextID,
		hashID:               hashID,
		username:             puInfo.Runtime.Options().UserID,
		autoport:             puInfo.Runtime.Options().AutoPort,
		managementID:         puInfo.Policy.ManagementID(),
		managementNamespace:  puInfo.Policy.ManagementNamespace(),
		puType:               puInfo.Runtime.PUType(),
		identity:             puInfo.Policy.Identity(),
		annotations:          puInfo.Policy.Annotations(),
		compressedTags:       puInfo.Policy.CompressedTags(),
		externalIPCache:      cache.NewCacheWithExpiration("External IP Cache", timeout),
		ApplicationACLs:      acls.NewACLCache(),
		networkACLs:          acls.NewACLCache(),
		DNSACLs:              puInfo.Policy.DNSNameACLs(),
		mark:                 puInfo.Runtime.Options().CgroupMark,
		scopes:               puInfo.Policy.Scopes(),
		counters:             counters.NewCounters(),
		puInfo:               puInfo,
		tokenAccessor:        tokenAccessor,
		appDefaultFlowPolicy: &policy.FlowPolicy{Action: puInfo.Policy.AppDefaultPolicyAction(), PolicyID: "default", ServiceID: "default"},
		netDefaultFlowPolicy: &policy.FlowPolicy{Action: puInfo.Policy.NetDefaultPolicyAction(), PolicyID: "default", ServiceID: "default"},
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

	nsHash, err := tagutils.Hash(pu.managementNamespace)
	if err != nil {
		return nil, fmt.Errorf("unable to hash namespace: %w", err)
	}
	pu.managementNamespaceHash = nsHash

	ctx, cancel := context.WithCancel(context.Background())
	pu.ctxCancel = cancel

	// tokenAccessor is nil with envoy authorizer enforcer. We
	// don't need our datapath in that case.
	if tokenAccessor != nil {
		pu.synToken = pu.createSynToken(nil, claimsheader.NewClaimsHeader())

		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(constants.SynTokenRefreshTime):

					synToken := pu.createSynToken(nil, claimsheader.NewClaimsHeader())
					pu.Lock()
					pu.synToken = synToken
					pu.Unlock()
				}
			}
		}()
	}

	return pu, nil
}

func (p *PUContext) createSynToken(pingPayload *policy.PingPayload, claimsHeader *claimsheader.ClaimsHeader) *synTokenInfo {

	var datapathKeyPair ephemeralkeys.KeyAccessor
	var err error
	var nonce []byte

	for {
		datapathKeyPair, err = ephemeralkeys.New()

		if err != nil {
			// can generate errors only when the urandom io read buffer is full. retry till we succeed.
			time.Sleep(10 * time.Millisecond)
			continue
		}

		break
	}

	for {
		// can generate errors only when the urandom io read buffer is full. retry till we succeed.
		nonce, err = crypto.GenerateRandomBytes(16)
		if err != nil {
			continue
		}

		break
	}

	claims := &tokens.ConnectionClaims{
		LCL:   nonce,
		DEKV1: datapathKeyPair.DecodingKeyV1(),
		DEKV2: datapathKeyPair.DecodingKeyV2(),
		CT:    p.CompressedTags(),
		ID:    p.ManagementID(),
		P:     pingPayload,
	}

	datapathSecret := ephemeralkeys.GetDatapathSecret()
	var encodedBuf [tokens.ClaimsEncodedBufSize]byte

	token, err := p.tokenAccessor.CreateSynPacketToken(claims, encodedBuf[:], nonce, claimsHeader, datapathSecret)
	if err != nil {
		zap.L().Error("Can not create syn packet token", zap.Error(err))
		return nil
	}

	ephKeySignV1, err := p.tokenAccessor.Sign(datapathKeyPair.DecodingKeyV1(), datapathSecret.EncodingKey().(*ecdsa.PrivateKey))
	if err != nil {
		zap.L().Error("Can not sign the ephemeral public key", zap.Error(err))
		return nil
	}

	ephKeySignV2, err := p.tokenAccessor.Sign(datapathKeyPair.DecodingKeyV2(), datapathSecret.EncodingKey().(*ecdsa.PrivateKey))
	if err != nil {
		zap.L().Error("Can not sign the ephemeral public key", zap.Error(err))
		return nil
	}

	privateKey := datapathKeyPair.PrivateKey()
	return &synTokenInfo{datapathSecret: datapathSecret,
		privateKey:      privateKey,
		publicKeyV1:     datapathKeyPair.DecodingKeyV1(),
		publicKeySignV1: ephKeySignV1,
		publicKeyV2:     datapathKeyPair.DecodingKeyV2(),
		publicKeySignV2: ephKeySignV2,
		token:           token}
}

//StopProcessing cancels the context such that all the goroutines can return.
func (p *PUContext) StopProcessing() {
	p.ctxCancel()
}

//GetSynToken returns the cached syntoken if the datapath secret has not changed or the ping payload is present.
func (p *PUContext) GetSynToken(pingPayload *policy.PingPayload, nonce [16]byte, claimsHeader *claimsheader.ClaimsHeader) (secrets.Secrets, *ephemeralkeys.PrivateKey, []byte) {

	if pingPayload != nil {
		synToken := p.createSynToken(pingPayload, claimsHeader)
		return synToken.datapathSecret, synToken.privateKey, synToken.token
	}

	p.RLock()
	synToken := p.synToken
	p.RUnlock()

	if synToken.datapathSecret != ephemeralkeys.GetDatapathSecret() {
		synToken = p.createSynToken(nil, claimsheader.NewClaimsHeader())
		p.Lock()
		p.synToken = synToken
		p.Unlock()
	}

	p.tokenAccessor.Randomize(synToken.token, nonce[:]) //nolint

	return synToken.datapathSecret, synToken.privateKey, synToken.token
}

//GetSecrets returns the datapath secret and ephemeral public and private key
func (p *PUContext) GetSecrets() (secrets.Secrets, *ephemeralkeys.PrivateKey, []byte, []byte, []byte, []byte) {
	p.RLock()
	synToken := p.synToken
	p.RUnlock()

	if synToken.datapathSecret != ephemeralkeys.GetDatapathSecret() {
		synToken = p.createSynToken(nil, claimsheader.NewClaimsHeader())
		p.Lock()
		p.synToken = synToken
		p.Unlock()
	}

	return ephemeralkeys.GetDatapathSecret(), synToken.privateKey, synToken.publicKeyV1, synToken.publicKeySignV1, synToken.publicKeyV2, synToken.publicKeySignV2
}

// GetPolicyFromFQDN gets the list of policies that are mapped with the hostname
func (p *PUContext) GetPolicyFromFQDN(fqdn string) ([]policy.PortProtocolPolicy, string, error) {
	p.RLock()
	defer p.RUnlock()

	// If we find a direct match, return policy
	if v, ok := p.DNSACLs[fqdn]; ok {
		return v, fqdn, nil
	}

	// Try if there is a wildcard match
	for policyName, policy := range p.DNSACLs {
		if wildcard.MatchSimple(policyName, fqdn) {
			return policy, policyName, nil
		}
	}

	return nil, "", fmt.Errorf("Policy doesn't exist")
}

// DependentServices searches if the PU has a dependent service on this FQDN. If yes,
// it returns the ports for that service.
func (p *PUContext) DependentServices(fqdn string) []*policy.ApplicationService {
	p.RLock()
	defer p.RUnlock()

	dependentServices := []*policy.ApplicationService{}

	for _, dependentService := range p.puInfo.Policy.DependentServices() {
		for _, name := range dependentService.NetworkInfo.FQDNs {
			if fqdn == name {
				dependentServices = append(dependentServices, dependentService)
			}
		}
	}

	return dependentServices
}

// UsesFQDN indicates whether this PU policy has an ACL or Service that uses an FQDN
func (p *PUContext) UsesFQDN() bool {
	p.RLock()
	defer p.RUnlock()

	if len(p.DNSACLs) > 0 {
		return true
	}

	for _, dependentService := range p.puInfo.Policy.DependentServices() {
		for _, name := range dependentService.NetworkInfo.FQDNs {
			if name != "" {
				return true
			}
		}
	}

	return false
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

// ManagementNamespaceHash returns the management namespace hash
func (p *PUContext) ManagementNamespaceHash() string {
	return p.managementNamespaceHash
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

	return p.networkACLs.GetMatchingAction(packet.SourceAddress(), packet.DestPort(), packet.IPProto(), p.netDefaultFlowPolicy)
}

// NetworkACLPolicyFromAddr retrieve the policy given an address and port.
func (p *PUContext) NetworkACLPolicyFromAddr(addr net.IP, port uint16, protocol uint8) (report *policy.FlowPolicy, action *policy.FlowPolicy, err error) {
	defer p.RUnlock()
	p.RLock()

	return p.networkACLs.GetMatchingAction(addr, port, protocol, p.netDefaultFlowPolicy)
}

// ApplicationICMPACLPolicy retrieve the policy for ICMP
func (p *PUContext) ApplicationICMPACLPolicy(ip net.IP, icmpType, icmpCode int8) (report *policy.FlowPolicy, action *policy.FlowPolicy, err error) {
	return p.ApplicationACLs.GetMatchingICMPAction(ip, icmpType, icmpCode, p.appDefaultFlowPolicy)
}

// NetworkICMPACLPolicy retrieve the policy for ICMP
func (p *PUContext) NetworkICMPACLPolicy(ip net.IP, icmpType, icmpCode int8) (report *policy.FlowPolicy, action *policy.FlowPolicy, err error) {
	return p.networkACLs.GetMatchingICMPAction(ip, icmpType, icmpCode, p.netDefaultFlowPolicy)
}

// ApplicationACLPolicyFromAddr retrieve the policy given an address and port.
func (p *PUContext) ApplicationACLPolicyFromAddr(addr net.IP, port uint16, protocol uint8) (report *policy.FlowPolicy, action *policy.FlowPolicy, err error) {
	defer p.RUnlock()
	p.RLock()

	return p.ApplicationACLs.GetMatchingAction(addr, port, protocol, p.appDefaultFlowPolicy)
}

// UpdateApplicationACLs updates the application ACL policy
func (p *PUContext) UpdateApplicationACLs(rules policy.IPRuleList) error {
	defer p.Unlock()
	p.Lock()

	return p.ApplicationACLs.AddRuleList(rules)
}

// FlushApplicationACL removes the application ACLs which are indexed with (ip, mask) key for all protocols and ports
func (p *PUContext) FlushApplicationACL(addr net.IP, mask int) {
	defer p.Unlock()
	p.Lock()
	p.ApplicationACLs.RemoveIPMask(addr, mask)
}

// RemoveApplicationACL removes the application ACLs for a specific IP address for all protocols and ports that match a policy.
// NOTE: Rules need to be a full port/policy match in order to get removed. Partial port matches in ranges will not get removed.
func (p *PUContext) RemoveApplicationACL(ipaddress string, protocols, ports []string, policy *policy.FlowPolicy) error {
	defer p.Unlock()
	p.Lock()

	address, err := acls.ParseAddress(ipaddress)
	if err != nil {
		return err
	}

	for _, protocol := range protocols {
		if err := p.ApplicationACLs.RemoveRulesForAddress(address, protocol, ports, policy); err != nil {
			return err
		}
	}
	return nil
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
	defaultFlowReport *policy.FlowPolicy,
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
			if finalAction.Action.Logged() {
				packetAction.Action = packetAction.Action | policy.Log
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

	// Clone the default because someone is changing the returned one
	packetAction = defaultFlowReport.Clone()

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
	return p.searchRules(p.txt, tags, skipRejectPolicies, p.appDefaultFlowPolicy)
}

// SearchRcvRules searches both receive and observed receive rules and returns the index and action
func (p *PUContext) SearchRcvRules(
	tags *policy.TagStore,
) (report *policy.FlowPolicy, packet *policy.FlowPolicy) {
	return p.searchRules(p.rcv, tags, false, p.netDefaultFlowPolicy)
}

// LookupLogPrefix lookup the log prefix from the key
func (p *PUContext) LookupLogPrefix(key string) (string, bool) {
	p.Lock()
	defer p.Unlock()
	if p.puInfo == nil || p.puInfo.Policy == nil {
		return "", false
	}
	return p.puInfo.Policy.LookupLogPrefix(key)
}
