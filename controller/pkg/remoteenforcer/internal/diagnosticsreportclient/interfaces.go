package diagnosticsreportclient

import "context"

// DiagnosticsReportClient defines the interface for dns reporting by the remote enforcer
type DiagnosticsReportClient interface {
	Run(ctx context.Context) error
}
