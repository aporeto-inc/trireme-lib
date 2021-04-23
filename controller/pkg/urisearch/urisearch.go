package urisearch

import (
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

type node struct {
	children map[string]*node
	leaf     bool
	data     interface{}
}

// APICache represents an API cache.
type APICache struct {
	methodRoots map[string]*node
	ID          string
	External    bool
}

type scopeRule struct {
	rule *policy.HTTPRule
}

// NewAPICache creates a new API cache
func NewAPICache(rules []*policy.HTTPRule, id string, external bool) *APICache {
	a := &APICache{
		methodRoots: map[string]*node{},
		ID:          id,
		External:    external,
	}

	for _, rule := range rules {
		sc := &scopeRule{
			rule: rule,
		}
		for _, method := range rule.Methods {
			if _, ok := a.methodRoots[method]; !ok {
				a.methodRoots[method] = &node{}
			}
			for _, uri := range rule.URIs {
				insert(a.methodRoots[method], uri, sc)
			}
		}
	}

	return a
}

// FindRule finds a rule in the APICache without validating scopes
func (c *APICache) FindRule(verb, uri string) (bool, *policy.HTTPRule) {
	found, rule := c.Find(verb, uri)
	if rule == nil {
		return found, nil
	}
	if policyRule, ok := rule.(*scopeRule); ok {
		return found, policyRule.rule
	}
	return false, nil
}

// FindAndMatchScope finds the rule and returns true only if the scope matches
// as well. It also returns true of this was a public rule, allowing the callers
// to decide how to present the data or potentially what to do if authorization
// fails.
func (c *APICache) FindAndMatchScope(verb, uri string, attributes []string) (bool, bool) {
	found, rule := c.Find(verb, uri)
	if !found || rule == nil {
		return false, false
	}
	policyRule, ok := rule.(*scopeRule)
	if !ok {
		return false, false
	}
	if policyRule.rule.Public {
		return true, true
	}
	return c.MatchClaims(policyRule.rule.ClaimMatchingRules, attributes), false
}

// MatchClaims receives a set of claim matchibg rules and a set of claims
// and returns true of the claims match the rules.
func (c *APICache) MatchClaims(rules [][]string, claims []string) bool {

	claimsMap := map[string]struct{}{}
	for _, claim := range claims {
		claimsMap[claim] = struct{}{}
	}

	var matched int
	for _, clause := range rules {
		matched = len(clause)
		for _, claim := range clause {
			if _, ok := claimsMap[claim]; ok {
				matched--
			}
			if matched == 0 {
				return true
			}
		}
	}
	return false
}

// Find finds a URI in the cache and returns true and the data if found.
// If not found it returns false.
func (c *APICache) Find(verb, uri string) (bool, interface{}) {
	root, ok := c.methodRoots[verb]
	if !ok {
		return false, nil
	}
	return search(root, uri)
}

// parse parses a URI and splits into prefix, suffix
func parse(s string) (string, string) {
	if s == "/" {
		return s, ""
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '/' {
			return s[0:i], s[i:]
		}
	}

	return s, ""
}

// insert adds an api to the api cache
func insert(n *node, api string, data interface{}) {
	if len(api) == 0 {
		n.data = data
		n.leaf = true
		return
	}

	prefix, suffix := parse(api)

	// root node or terminal node
	if prefix == "/" {
		n.data = data
		n.leaf = true
		return
	}

	if n.children == nil {
		n.children = map[string]*node{}
	}

	// If there is no child, add the new child.
	next, ok := n.children[prefix]
	if !ok {
		next = &node{}
		n.children[prefix] = next
	}

	insert(next, suffix, data)
}

func search(n *node, api string) (found bool, data interface{}) {

	prefix, suffix := parse(api)

	if prefix == "/" {
		if n.leaf {
			return true, n.data
		}
	}

	next, foundPrefix := n.children[prefix]
	// We found either an exact match or a * match
	if foundPrefix {
		matchedChildren, data := search(next, suffix)
		if matchedChildren {
			return true, data
		}
	}

	// If not found, try the ignore operator.
	next, foundPrefix = n.children["/?"]
	if foundPrefix {
		matchedChildren, data := search(next, suffix)
		if matchedChildren {
			return true, data
		}
	}

	// If not found, try the * operator and ignore the rest of path.
	next, foundPrefix = n.children["/*"]
	if foundPrefix {
		for len(suffix) > 0 {
			matchedChildren, data := search(next, suffix)
			if matchedChildren {
				return true, data
			}
			prefix, suffix = parse(suffix)
		}
		matchedChildren, data := search(next, "/")
		if matchedChildren {
			return true, data
		}
	}

	if n.leaf && len(prefix) == 0 {
		return true, n.data
	}

	return false, nil
}
