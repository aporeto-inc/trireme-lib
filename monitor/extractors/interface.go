package extractors

import (
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"
)

// EventMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// EventInfo. The EventInfo is generic and is provided over the RPC interface
type EventMetadataExtractor func(*common.EventInfo) (*policy.PURuntime, error)
