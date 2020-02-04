package client

import "context"

// Reporter interface provides functions to start/stop a remote client
// A remote client is an active component which is responsible for collecting
// events collected by datapath and ship them to the master enforcer.
type Reporter interface {
	Run(ctx context.Context) error
	Send() error
}
