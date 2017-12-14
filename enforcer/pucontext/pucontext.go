package pucontext

import (
	"sync"
	"time"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/acls"
	"github.com/aporeto-inc/trireme-lib/enforcer/lookup"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
)

// PUContext holds data indexed by the PU ID
type PUContext struct {
	ID                    string
	ManagementID          string
	Identity              *policy.TagStore
	Annotations           *policy.TagStore
	rejectTxtRules        *lookup.PolicyDB
	observeRejectTxtRules *lookup.PolicyDB
	acceptTxtRules        *lookup.PolicyDB
	observeAcceptTxtRules *lookup.PolicyDB
	rejectRcvRules        *lookup.PolicyDB
	observeRejectRcvRules *lookup.PolicyDB
	acceptRcvRules        *lookup.PolicyDB
	observeAcceptRcvRules *lookup.PolicyDB
	ApplicationACLs       *acls.ACLCache
	NetworkACLS           *acls.ACLCache
	ExternalIPCache       cache.DataStore
	Extension             interface{}
	IP                    string
	Mark                  string
	ProxyPort             string
	Ports                 []string
	PUType                constants.PUType
	SynToken              []byte
	SynServiceContext     []byte
	SynExpiration         time.Time
	sync.Mutex
}

// createRuleDBs creates the database of rules from the policy
func (p *PUContext) createRuleDBs(policyRules policy.TagSelectorList) (*lookup.PolicyDB, *lookup.PolicyDB, *lookup.PolicyDB, *lookup.PolicyDB) {

	rejectRules := lookup.NewPolicyDB()
	rejectObserveRules := lookup.NewPolicyDB()
	acceptRules := lookup.NewPolicyDB()
	acceptObserveRules := lookup.NewPolicyDB()

	for _, rule := range policyRules {
		if rule.Policy.Action.Accepted() {
			if rule.Policy.Action.Observed() {
				acceptObserveRules.AddPolicy(rule)
			} else {
				acceptRules.AddPolicy(rule)
			}
		} else if rule.Policy.Action.Rejected() {
			if rule.Policy.Action.Observed() {
				rejectObserveRules.AddPolicy(rule)
			} else {
				rejectRules.AddPolicy(rule)
			}
		} else {
			continue
		}
	}

	return acceptRules, acceptObserveRules, rejectRules, rejectObserveRules
}

// CreateRcvRules create receive rules for this PU based on the update of the policy.
func (p *PUContext) CreateRcvRules(policyRules policy.TagSelectorList) {
	p.acceptRcvRules, p.observeAcceptRcvRules, p.rejectRcvRules, p.observeRejectRcvRules = p.createRuleDBs(policyRules)
}

// CreateTxtRules create receive rules for this PU based on the update of the policy.
func (p *PUContext) CreateTxtRules(policyRules policy.TagSelectorList) {
	p.acceptTxtRules, p.observeAcceptTxtRules, p.rejectTxtRules, p.observeRejectTxtRules = p.createRuleDBs(policyRules)
}

// SearchRejectTxtRules searches both receive and observed receive rules and returns the index and action
func (p *PUContext) SearchRejectTxtRules(tags *policy.TagStore) (int, *policy.FlowPolicy) {

	index, action := p.rejectTxtRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	return -1, nil
}

// SearchAcceptTxtRules searches both receive and observed receive rules and returns the index and action
func (p *PUContext) SearchAcceptTxtRules(tags *policy.TagStore) (int, *policy.FlowPolicy) {

	// Order of searches is:
	//  a. Observed rejected rules - reported as drop-observed but we allow packets. When this policy will be converted to a 'non-observed' policy, we will report it as dropped and also drop packets.
	//  b. Accepted rules - reported as accept and packets are allowed.
	//  c. Observerd accepted rules - reported as accept-observed and packets are allowed.
	index, action := p.observeRejectTxtRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	index, action = p.acceptTxtRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	index, action = p.observeAcceptTxtRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	return -1, nil
}

// SearchRejectRcvRules searches both receive and observed receive rules and returns the index and action
func (p *PUContext) SearchRejectRcvRules(tags *policy.TagStore) (int, *policy.FlowPolicy) {

	index, action := p.rejectRcvRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	return -1, nil
}

// SearchAcceptRcvRules searches both receive and observed receive rules and returns the index and action
func (p *PUContext) SearchAcceptRcvRules(tags *policy.TagStore) (int, *policy.FlowPolicy) {

	// Order of searches is:
	//  a. Observed rejected rules - reported as drop-observed but we allow packets. When this policy will be converted to a 'non-observed' policy, we will report it as dropped and also drop packets.
	//  b. Accepted rules - reported as accept and packets are allowed.
	//  c. Observerd accepted rules - reported as accept-observed and packets are allowed.
	index, action := p.observeRejectRcvRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	index, action = p.acceptRcvRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	index, action = p.observeAcceptRcvRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	return -1, nil
}
