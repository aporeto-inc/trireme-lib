package dnsreportclient

import "context"

type DNSReportClient interface {
	Run(ctx context.Context) error
}
