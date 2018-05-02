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
	methodRoots map[string]*node
	ID          string
	External    bool
}

// NewAPICache creates a new API cache
func NewAPICache(rules []*policy.HTTPRule, id string, external bool) *APICache {
	a := &APICache{
		methodRoots: map[string]*node{},
		ID:          id,
		External:    external,
	}

	for _, rule := range rules {
		for _, method := range rule.Methods {
			if _, ok := a.methodRoots[method]; !ok {
				a.methodRoots[method] = &node{}
			}
			for _, uri := range rule.URIs {
				insert(a.methodRoots[method], uri, rule)
			}
		}
	}

	return a
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
			return s[0:i], s[i:len(s)]
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
	if !foundPrefix {
		// If not found, try the star
		next, foundPrefix = n.children["/*"]
	}

	// We found either an exact match or a * match
	if foundPrefix {
		return search(next, suffix)
	}

	if n.leaf && len(prefix) == 0 {
		return true, n.data
	}

	return false, nil
}
