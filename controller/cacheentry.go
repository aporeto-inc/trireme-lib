package controller

import "github.com/aporeto-inc/trireme/policy"

type controllerCacheEntry struct {
	index       int
	ips         map[string]string
	ingressACLs []policy.IPRule
	egressACLs  []policy.IPRule
}
