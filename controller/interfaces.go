package controller

import (
	"context"

	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// TriremeController is the main API of the Trireme controller
type TriremeController interface {
	// Run initializes and runs the controller.
	Run(ctx context.Context) error

	// ProcessEvent processes an event or policy update. Returns false if the container
	ProcessEvent(ctx context.Context, event common.Event, id string, policy *policy.PUPolicy, runtime *policy.PURuntime) (err error)

	// UpdatePolicy updates the policy of the isolator for a container.
	UpdatePolicy(contextID string, policy *policy.PUPolicy, runtime *policy.PURuntime) error

	// UpdateSecrets updates the secrets of running enforcers managed by trireme. Remote enforcers will get the secret updates with the next policy push
	UpdateSecrets(secrets secrets.Secrets) error
}
