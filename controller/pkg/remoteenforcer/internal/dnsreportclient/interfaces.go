package dnsreportclient

import "context"

// DNSReportClient defines the interface for dns reporting by the remote enforcer
type DNSReportClient interface {
	Run(ctx context.Context) error
}
