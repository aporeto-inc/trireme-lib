package reports

import "context"

// ReportsClient defines the reporrting interface.
type ReportsClient interface {
	Run(ctx context.Context) error
}
