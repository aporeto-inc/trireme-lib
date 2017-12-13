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
	RejectTxtRules        *lookup.PolicyDB
	ObserveRejectTxtRules *lookup.PolicyDB
	AcceptTxtRules        *lookup.PolicyDB
	ObserveAcceptTxtRules *lookup.PolicyDB
	RejectRcvRules        *lookup.PolicyDB
	ObserveRejectRcvRules *lookup.PolicyDB
	AcceptRcvRules        *lookup.PolicyDB
	ObserveAcceptRcvRules *lookup.PolicyDB
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
		if rule.Policy.Action&policy.Accept != 0 {
			if rule.Policy.Action&policy.Observe != 0 {
				acceptObserveRules.AddPolicy(rule)
			} else {
				acceptRules.AddPolicy(rule)
			}
		} else if rule.Policy.Action&policy.Reject != 0 {
			if rule.Policy.Action&policy.Observe != 0 {
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
	p.AcceptRcvRules, p.ObserveAcceptRcvRules, p.RejectRcvRules, p.ObserveRejectRcvRules = p.createRuleDBs(policyRules)
}

// CreateTxtRules create receive rules for this PU based on the update of the policy.
func (p *PUContext) CreateTxtRules(policyRules policy.TagSelectorList) {
	p.AcceptTxtRules, p.ObserveAcceptTxtRules, p.RejectTxtRules, p.ObserveRejectTxtRules = p.createRuleDBs(policyRules)
}

// SearchRejectTxtRules searches both receive and observed receive rules and returns the index and action
func (p *PUContext) SearchRejectTxtRules(tags *policy.TagStore) (int, *policy.FlowPolicy) {

	index, action := p.RejectTxtRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	index, action = p.ObserveRejectTxtRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	return -1, nil
}

// SearchAcceptTxtRules searches both receive and observed receive rules and returns the index and action
func (p *PUContext) SearchAcceptTxtRules(tags *policy.TagStore) (int, *policy.FlowPolicy) {

	index, action := p.AcceptTxtRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	index, action = p.ObserveAcceptTxtRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	return -1, nil
}

// SearchRejectRcvRules searches both receive and observed receive rules and returns the index and action
func (p *PUContext) SearchRejectRcvRules(tags *policy.TagStore) (int, *policy.FlowPolicy) {

	index, action := p.RejectRcvRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	index, action = p.ObserveRejectRcvRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	return -1, nil
}

// SearchAcceptRcvRules searches both receive and observed receive rules and returns the index and action
func (p *PUContext) SearchAcceptRcvRules(tags *policy.TagStore) (int, *policy.FlowPolicy) {

	index, action := p.AcceptRcvRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	index, action = p.ObserveAcceptRcvRules.Search(tags)
	if index >= 0 {
		return index, action.(*policy.FlowPolicy)
	}
	return -1, nil
}
