package pingreportclient

import "context"

// PingReportClient defines the interface for dns reporting by the remote enforcer
type PingReportClient interface {
	Run(ctx context.Context) error
}
