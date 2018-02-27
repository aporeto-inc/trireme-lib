package urisearch

import (
	"github.com/aporeto-inc/trireme-lib/policy"
)

type node struct {
	children map[string]*node
	verbs    map[string]struct{}
	leaf     bool
	data     interface{}
}

// APICache represents an API cache.
type APICache struct {
	root *node
}

// NewAPICache creates a new API cache
func NewAPICache(rules []*policy.HTTPRule) *APICache {
	a := &APICache{
		root: &node{},
	}

	empty := struct{}{}
	for _, rule := range rules {
		verbs := map[string]struct{}{}
		for _, verb := range rule.Verbs {
			verbs[verb] = empty
		}

		for _, uri := range rule.URIs {
			insert(a.root, uri, verbs, rule.Tags)
		}
	}

	return a
}

// Find finds a URI in the cache and returns true and the data if found.
// If not found it returns false.
func (c *APICache) Find(verb, uri string) (bool, interface{}) {
	return search(c.root, verb, uri)
}

// parse parses a URI and splits into prefix, suffix
func parse(s string) (string, string) {
	if s == "/" {
		return s, ""
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '/' {
			return s[0:i], s[i:len(s)]
		}
	}

	return s, ""
}

// insert adds an api to the api cache
func insert(n *node, api string, verbs map[string]struct{}, data interface{}) {
	if len(api) == 0 {
		n.data = data
		n.leaf = true
		n.verbs = verbs
		return
	}

	prefix, suffix := parse(api)

	// root node or terminal node
	if prefix == "/" {
		n.data = data
		n.leaf = true
		n.verbs = verbs
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

	insert(next, suffix, verbs, data)
}

func search(n *node, verb string, api string) (found bool, data interface{}) {
	prefix, suffix := parse(api)

	if prefix == "/" {
		if n.leaf {
			_, matched := n.verbs[verb]
			return matched, n.data
		}
	}

	next, foundPrefix := n.children[prefix]
	if !foundPrefix {
		// If not found, try the star
		next, foundPrefix = n.children["/*"]
	}

	// We found either an exact match or a * match
	if foundPrefix {
		return search(next, verb, suffix)
	}

	if n.leaf && len(prefix) == 0 {
		_, matched := n.verbs[verb]
		return matched, n.data
	}

	return false, nil
}
