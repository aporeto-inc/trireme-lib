// +build linux !darwin

package dnsproxy

import (
	"net"
	"time"

	"go.aporeto.io/trireme-lib/v11/collector"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/pucontext"
)

var (
	waitTimeBeforeReport = 30 * time.Second
)

type dnsReport struct {
	contextID  string
	nameLookup string
	error      string
	endpoint   collector.EndPoint
	namespace  string
}

func (p *Proxy) sendToCollector(report dnsReport, count int) {
	r := &collector.DNSRequestReport{
		NameLookup: report.nameLookup,
		Source:     &report.endpoint,
		Namespace:  report.namespace,
		Error:      report.error,
		Count:      count,
		Ts:         time.Now(),
	}
	p.collector.CollectDNSRequests(r)
}

func (p *Proxy) reportDNSRequests(chreport chan dnsReport) {
	dnsReports := map[dnsReport]int{}
	sendReport := make(chan dnsReport)
	deleteReport := make(chan dnsReport)

	for {
		select {
		case r := <-chreport:
			dnsReports[r]++
			switch dnsReports[r] {
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
			p.sendToCollector(r, dnsReports[r]-1)
			delete(dnsReports, r)
		case r := <-deleteReport:
			if dnsReports[r] == 1 {
				delete(dnsReports, r)
			}
		}
	}
}

func (p *Proxy) reportDNSLookup(name string, pucontext *pucontext.PUContext, srcIP net.IP, err string) {
	p.chreports <- dnsReport{
		contextID:  pucontext.ID(),
		nameLookup: name,
		error:      err,
		namespace:  pucontext.ManagementNamespace(),
		endpoint: collector.EndPoint{
			IP:   srcIP.String(),
			ID:   pucontext.ManagementID(),
			Type: collector.EnpointTypePU,
		}}
}
