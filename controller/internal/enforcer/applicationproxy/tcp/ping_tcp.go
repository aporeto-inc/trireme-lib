package tcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/pingrequest"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/gaia"
	"go.aporeto.io/gaia/x509extensions"
	"go.uber.org/zap"
)

// InitiatePing initiates the ping request
func (p *Proxy) InitiatePing(ctx context.Context, sctx *serviceregistry.ServiceContext, sdata *serviceregistry.DependentServiceData, pingConfig *policy.PingConfig) error {

	zap.L().Debug("Initiating L4 ping")

	for i := 0; i < pingConfig.Iterations; i++ {
		if err := p.sendPingRequest(ctx, pingConfig, sctx, sdata, i); err != nil {
			return err
		}
	}

	return nil
}

func (p *Proxy) sendPingRequest(
	ctx context.Context,
	pingConfig *policy.PingConfig,
	sctx *serviceregistry.ServiceContext,
	sdata *serviceregistry.DependentServiceData,
	iterationID int) error {

	pingID := pingConfig.ID
	destIP := pingConfig.IP
	destPort := pingConfig.Port

	_, netaction, _ := sctx.PUContext.ApplicationACLPolicyFromAddr(destIP, destPort, packet.IPProtocolTCP)

	pingErr := "dial"
	if e := pingConfig.Error(); e != "" {
		pingErr = e
	}

	pr := &collector.PingReport{
		PingID:               pingID,
		IterationID:          iterationID,
		PUID:                 sctx.PUContext.ManagementID(),
		Namespace:            sctx.PUContext.ManagementNamespace(),
		Protocol:             6,
		ServiceType:          "L4",
		AgentVersion:         p.agentVersion.String(),
		ApplicationListening: false,
		ACLPolicyID:          netaction.PolicyID,
		ACLPolicyAction:      netaction.Action,
		Error:                pingErr,
		TargetTCPNetworks:    pingConfig.TargetTCPNetworks,
		ExcludedNetworks:     pingConfig.ExcludedNetworks,
		Type:                 gaia.PingProbeTypeRequest,
		RemoteEndpointType:   collector.EndPointTypeExternalIP,
		ClaimsType:           gaia.PingProbeClaimsTypeReceived,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypePlain,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeTransmitted,
	}

	defer p.collector.CollectPingEvent(pr)

	conn, err := dial(ctx, destIP, destPort, p.mark)
	if err != nil {
		return err
	}
	defer conn.Close() // nolint: errcheck

	src := conn.RemoteAddr().(*net.TCPAddr)
	pl := p.getPolicyReporter(sctx.PUContext, src.IP, src.Port, destIP, int(destPort), sdata.ServiceObject)
	pl.client = true

	// ServerName: Use first configured FQDN or the destination IP
	serverName, err := common.GetTLSServerName(conn.RemoteAddr().String(), sdata.ServiceObject)
	if err != nil {
		return fmt.Errorf("unable to get the server name: %s", err)
	}

	// Encrypt Down Connection
	p.RLock()
	ca := p.caPool
	p.RUnlock()

	tlsCert, err := tls.X509KeyPair([]byte(pingConfig.ServiceCertificate), []byte(pingConfig.ServiceKey))
	if err != nil {
		return fmt.Errorf("unable to parse X509 certificate: %w", err)
	}

	certs := []tls.Certificate{
		tlsCert,
	}

	t, err := getClientTLSConfig(ca, certs, serverName, false)
	if err != nil {
		return fmt.Errorf("unable to generate tls configuration: %s", err)
	}

	// Do TLS
	tlsConn := tls.Client(conn, t)
	defer tlsConn.Close() // nolint errcheck

	payload := &policy.PingPayload{
		PingID:      pingID,
		IterationID: iterationID,
		ServiceType: policy.ServiceTCP,
	}

	host := fmt.Sprintf("https://%s:%d", destIP, destPort)
	data, err := pingrequest.CreateRaw(host, payload)
	if err != nil {
		return err
	}

	laddr := tlsConn.LocalAddr().(*net.TCPAddr)
	raddr := tlsConn.RemoteAddr().(*net.TCPAddr)

	startTime := time.Now()
	if err := write(tlsConn, data); err != nil {
		pr.Error = err.Error()
		pr.FourTuple = fmt.Sprintf(
			"%s:%s:%d:%d",
			laddr.IP.String(),
			raddr.IP.String(),
			laddr.Port,
			raddr.Port,
		)
		return err
	}

	pr.Error = ""
	pr.RTT = time.Since(startTime).String()
	pr.PayloadSize = len(data)
	pr.ApplicationListening = true
	pr.Type = gaia.PingProbeTypeResponse
	pr.FourTuple = fmt.Sprintf(
		"%s:%s:%d:%d",
		raddr.IP.String(),
		laddr.IP.String(),
		raddr.Port,
		laddr.Port,
	)

	if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
		return extract(pr, tlsConn.ConnectionState().PeerCertificates[0], pl)
	}

	return nil
}

func (p *Proxy) processPingRequest(conn *tls.Conn, pl *lookup) error {

	zap.L().Debug("Processing ping request")

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}

	var dst bytes.Buffer
	if _, err := io.Copy(&dst, conn); err != nil {
		return err
	}

	pp, err := pingrequest.ExtractRaw(dst.Bytes())
	if err != nil {
		return err
	}

	pr := &collector.PingReport{
		PingID:          pp.PingID,
		IterationID:     pp.IterationID,
		Type:            gaia.PingProbeTypeRequest,
		PUID:            pl.puContext.ManagementID(),
		Namespace:       pl.puContext.ManagementNamespace(),
		PayloadSize:     len(dst.Bytes()),
		PayloadSizeType: gaia.PingProbePayloadSizeTypeReceived,
		Protocol:        6,
		ServiceType:     "L4",
		FourTuple: fmt.Sprintf("%s:%s:%d:%d",
			pl.SourceIP.String(),
			pl.DestIP.String(),
			pl.SourcePort,
			pl.DestPort),
		AgentVersion:        p.agentVersion.String(),
		RemoteEndpointType:  collector.EndPointTypePU,
		IsServer:            true,
		ClaimsType:          gaia.PingProbeClaimsTypeReceived,
		RemoteNamespaceType: gaia.PingProbeRemoteNamespaceTypePlain,
		TargetTCPNetworks:   true,
		ExcludedNetworks:    false,
	}

	if pp.ServiceType != policy.ServiceTCP {
		pr.Error = fmt.Sprintf("service type mismatch, expected: %d, actual: %d", policy.ServiceTCP, pp.ServiceType)
	}

	if len(conn.ConnectionState().PeerCertificates) > 0 {
		if err := extract(pr, conn.ConnectionState().PeerCertificates[0], pl); err != nil {
			return err
		}
	}

	p.collector.CollectPingEvent(pr)

	return nil
}

func extract(pr *collector.PingReport, cert *x509.Certificate, pl *lookup) error {

	pr.RemotePUID = cert.Subject.CommonName
	pr.RemoteEndpointType = collector.EndPointTypePU
	if len(cert.Subject.Organization) > 0 {
		pr.RemoteNamespace = cert.Subject.Organization[0]
	}
	pr.PeerCertIssuer = cert.Issuer.String()
	pr.PeerCertSubject = cert.Subject.String()
	pr.PeerCertExpiry = cert.NotAfter

	if found, controller := common.ExtractExtension(x509extensions.Controller(), cert.Extensions); found {
		pr.RemoteController = string(controller)
	}

	if found, value := common.ExtractExtension(x509extensions.IdentityTags(), cert.Extensions); found {

		claims := []string{}
		if err := json.Unmarshal(value, &claims); err != nil {
			return fmt.Errorf("unable to unmarshal tags: %w", err)
		}

		pr.Claims = claims

		tags := policy.NewTagStoreFromSlice(claims)
		_, pkt := pl.Policy(tags)

		pr.PolicyID = pkt.PolicyID
		pr.PolicyAction = pkt.Action
		if pkt.Action.Rejected() {
			pr.Error = collector.PolicyDrop
		}
	}

	return nil
}

func pingEnabled(conn *tls.Conn) bool {

	peerCerts := conn.ConnectionState().PeerCertificates
	if len(peerCerts) <= 0 {
		return false
	}

	found, _ := common.ExtractExtension(x509extensions.Ping(), peerCerts[0].Extensions)
	return found
}

func dial(ctx context.Context, ip net.IP, port uint16, mark int) (net.Conn, error) {

	raddr := &net.TCPAddr{
		IP:   ip,
		Port: int(port),
	}

	d := net.Dialer{
		Timeout: 5 * time.Second,
		Control: markedconn.ControlFunc(mark, false, nil),
	}
	return d.DialContext(ctx, "tcp", raddr.String())
}

func write(conn net.Conn, data []byte) error {

	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}

	n, err := conn.Write(data)
	if err != nil && err != io.EOF {
		return err
	}

	if n != len(data) {
		return fmt.Errorf("failed to write data, expected: %v, written: %v", len(data), n)
	}

	return nil
}
