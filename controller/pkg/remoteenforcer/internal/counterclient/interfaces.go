package counterclient

import "context"

// CounterClient interface provides a start function. the client is used to post counter collected
//  back to the master enforcer
type CounterClient interface {
	Run(ctx context.Context) error
}
