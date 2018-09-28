package nfqdatapath

import "context"

// NfqDatapath provides methods implemented by the packet processor
type NfqDatapath interface {
	StartPacketProcessor(ctx context.Context)
}
