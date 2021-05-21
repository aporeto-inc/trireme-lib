// +build linux windows

package dnsproxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
)

var (
	waitTimeBeforeReport = 5 * time.Minute
)

type dnsReport struct {
	key        string
	contextID  string
	nameLookup string
	error      string
	source     collector.EndPoint
	dest       collector.EndPoint
	namespace  string
	ips        []string
}

func (p *Proxy) sendToCollector(report dnsReport, count int) {
	r := &collector.DNSRequestReport{
		ContextID:   report.contextID,
		NameLookup:  report.nameLookup,
		Source:      &report.source,
		Destination: &report.dest,
		Namespace:   report.namespace,
		Error:       report.error,
		Count:       count,
		Ts:          time.Now(),
		IPs:         report.ips,
	}
	p.collector.CollectDNSRequests(r)
}

func (p *Proxy) reportDNSRequests(ctx context.Context, chreport chan dnsReport) {
	dnsReports := map[string]int{}
	sendReport := make(chan dnsReport)
	deleteReport := make(chan dnsReport)

	for {
		select {
		case r := <-chreport:
			dnsReports[r.key]++
			switch dnsReports[r.key] {
			case 1:
				// dispatch immediately
				p.sendToCollector(r, 1)
				go func(r dnsReport) {
					<-time.After(waitTimeBeforeReport)
					deleteReport <- r
				}(r)
			case 2:
				go func(r dnsReport) {
					<-time.After(waitTimeBeforeReport)
					sendReport <- r
				}(r)
			}
		case r := <-sendReport:
			p.sendToCollector(r, dnsReports[r.key]-1)
			delete(dnsReports, r.key)
		case r := <-deleteReport:
			if dnsReports[r.key] == 1 {
				delete(dnsReports, r.key)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (p *Proxy) reportDNSLookup(name string, pucontext *pucontext.PUContext, srcIP net.IP, srcPort uint16, dnsIP net.IP, dnsPort uint16, ips []string, err string) {
	p.chreports <- dnsReport{
		contextID:  pucontext.ID(),
		nameLookup: name,
		error:      err,
		namespace:  pucontext.ManagementNamespace(),
		source: collector.EndPoint{
			IP:   srcIP.String(),
			Port: srcPort,
			ID:   pucontext.ManagementID(),
			Type: collector.EndPointTypePU,
		},
		dest: collector.EndPoint{
			IP:   dnsIP.String(),
			Port: dnsPort,
			ID:   pucontext.ManagementID(),
			Type: collector.EndPointTypePU,
		},
		ips: ips,
		key: fmt.Sprintf("%s:%s:%s:%s:%s:%s", pucontext.ID(), name, err, pucontext.ManagementNamespace(), srcIP.String(), pucontext.ManagementID()),
	}
}
