package controller

import (
	"context"
	"time"

	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

// TriremeController is the main API of the Trireme controller
type TriremeController interface {
	// Run initializes and runs the controller.
	Run(ctx context.Context) error

	// CleanUp cleans all the supervisors and ACLs for a clean exit
	CleanUp() error

	// Enforce asks the controller to enforce policy on a processing unit
	Enforce(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime) (err error)

	// UnEnforce asks the controller to un-enforce policy on a processing unit
	UnEnforce(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime) (err error)

	// UpdatePolicy updates the policy of the isolator for a container.
	UpdatePolicy(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime) error

	// UpdateSecrets updates the secrets of running enforcers managed by trireme. Remote enforcers will get the secret updates with the next policy push
	UpdateSecrets(secrets secrets.Secrets) error

	// UpdateConfiguration updates the configuration of the controller. Only specific configuration
	// parameters can be updated during run time.
	UpdateConfiguration(cfg *runtime.Configuration) error
	DebugInfo
}

// DebugInfo is the interface implemented by controllers to support configuring debug options
type DebugInfo interface {
	// EnableReceivedPacketTracing will enable tracing of packets received by the datapath for a particular PU. Setting Disabled as tracing direction will stop tracing for the contextID
	EnableDatapathPacketTracing(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime, direction packettracing.TracingDirection, interval time.Duration) error
	// EnablePacketTracing enable iptables -j trace for the particular pu and is much wider packet stream.
	EnableIPTablesPacketTracing(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime, interval time.Duration) error
	// Ping runs ping based on the given config.
	Ping(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime, pingConfig *policy.PingConfig) error
}
