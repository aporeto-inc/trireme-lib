package debugclient

import "context"

// DebugClient interface provides a start function. the client is used to post packets collected
// Debuclient post packet report back to the master enforcer
type DebugClient interface {
	Run(ctx context.Context) error
	//	SendPacketReport()
}
