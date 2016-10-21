package supervisor

import "github.com/aporeto-inc/trireme/policy"

type supervisorCacheEntry struct {
	index       int
	ips         map[string]string
	ingressACLs []policy.IPRule
	egressACLs  []policy.IPRule
}
