package nflog

import (
	"context"
	"net"

	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
)

// NFLogger provides an interface for NFLog
type NFLogger interface {
	Run(ctx context.Context)
}

// GetPUContextFunc provides PU information given the id
type GetPUContextFunc func(hash string) (*pucontext.PUContext, error)

// reportPolicyFromAddr retrieves policy from aclcache based on transport direction.
func reportPolicyFromAddr(pu *pucontext.PUContext, ip net.IP, port uint16, app bool) (report *policy.FlowPolicy) {

	if app {
		report, _, _ = pu.ApplicationACLPolicyFromAddr(ip, port)
		return
	}

	report, _, _ = pu.NetworkACLPolicyFromAddr(ip, port)
	return
}
