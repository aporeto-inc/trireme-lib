package client

import (
	"go.aporeto.io/trireme-lib/v11/common"
)

// APIClient is the interface of the API client
type APIClient interface {
	// SendRequest will send a request to the server.
	SendRequest(event *common.EventInfo) error
}
