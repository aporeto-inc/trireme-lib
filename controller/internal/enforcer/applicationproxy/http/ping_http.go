package httpproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/apiauth"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/servicetokens"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/gaia"
	"go.aporeto.io/gaia/x509extensions"
	"go.uber.org/zap"
)

const fourTupleKey = "fourTuple"

type fourTuple struct {
	sourceAddress      net.IP
	destinationAddress net.IP
	sourcePort         int
	destinationPort    int
}

// InitiatePing starts an encrypted connection to the given config.
func (p *Config) InitiatePing(ctx context.Context, sctx *serviceregistry.ServiceContext, sdata *serviceregistry.DependentServiceData, pingConfig *policy.PingConfig) error {

	zap.L().Debug("Initiating L7 ping")

	for i := 0; i < pingConfig.Iterations; i++ {
		if err := p.sendPingRequest(ctx, pingConfig, sctx, sdata, i); err != nil {
			return err
		}
	}

	return nil
}

func (p *Config) sendPingRequest(
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
		ServiceID:            sdata.APICache.ID,
		PUID:                 sctx.PUContext.ManagementID(),
		Namespace:            sctx.PUContext.ManagementNamespace(),
		Protocol:             6,
		ServiceType:          "L7",
		AgentVersion:         p.agentVersion.String(),
		ApplicationListening: false,
		ACLPolicyID:          netaction.PolicyID,
		ACLPolicyAction:      netaction.Action,
		Error:                pingErr,
		TargetTCPNetworks:    pingConfig.TargetTCPNetworks,
		ExcludedNetworks:     pingConfig.ExcludedNetworks,
		Type:                 gaia.PingProbeTypeRequest,
		RemoteEndpointType:   collector.EndPointTypeExternalIP,
		Claims:               sctx.PUContext.Identity().GetSlice(),
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypePlain,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeTransmitted,
	}

	ft := &fourTuple{}

	p.RLock()
	encodingKey := p.secrets.EncodingKey()
	pubKey := p.secrets.TransmittedKey()
	p.RUnlock()

	pingPayload := &policy.PingPayload{
		PingID:      pingID,
		IterationID: iterationID,
	}

	token, err := servicetokens.CreateAndSign(
		"",
		sctx.PUContext.Identity().GetSlice(),
		sctx.PUContext.Scopes(),
		sctx.PUContext.ManagementID(),
		apiauth.DefaultValidity,
		encodingKey,
		pingPayload,
	)
	if err != nil {
		return err
	}

	networkDialerWithContext := func(ctx context.Context, _, addr string) (net.Conn, error) {

		conn, err := dial(ctx, addr, p.mark)
		if err != nil {
			return nil, fmt.Errorf("unable to dial remote: %s", err)
		}

		if v := ctx.Value(fourTupleKey); v != nil {
			if r, ok := v.(*fourTuple); ok {
				laddr := conn.LocalAddr().(*net.TCPAddr)
				raddr := conn.RemoteAddr().(*net.TCPAddr)
				r.sourceAddress = laddr.IP
				r.sourcePort = laddr.Port
				r.destinationAddress = raddr.IP
				r.destinationPort = raddr.Port
			}
		}

		return conn, nil
	}

	raddr := &net.TCPAddr{
		IP:   destIP,
		Port: int(destPort),
	}

	// ServerName: Use first configured FQDN or the destination IP
	serverName, err := common.GetTLSServerName(raddr.String(), sdata.ServiceObject)
	if err != nil {
		return fmt.Errorf("unable to get the server name: %s", err)
	}

	// Used to validate the hostname in the returned server certs.
	// TODO: Maybe we should elevate this as first class citizen ?
	p.tlsClientConfig.ServerName = serverName

	encryptedTransport := &http.Transport{
		TLSClientConfig:     p.tlsClientConfig,
		DialContext:         networkDialerWithContext,
		MaxIdleConnsPerHost: 2000,
		MaxIdleConns:        2000,
		ForceAttemptHTTP2:   true,
	}

	client := &http.Client{
		Transport: encryptedTransport,
		Timeout:   5 * time.Second,
	}

	host := fmt.Sprintf("https://%s:%d", destIP, destPort)
	ctxWithReport := context.WithValue(ctx, fourTupleKey, ft) // nolint: golint,staticcheck
	req, err := http.NewRequestWithContext(ctxWithReport, "GET", host, nil)
	if err != nil {
		return err
	}

	defer p.collector.CollectPingEvent(pr)

	pr.PayloadSize = len(pubKey) + len(token)

	req.Header.Add("X-APORETO-KEY", string(pubKey))
	req.Header.Add("X-APORETO-AUTH", token)

	startTime := time.Now()
	res, err := client.Do(req)
	if err != nil {
		pr.Error = err.Error()
		pr.FourTuple = fmt.Sprintf(
			"%s:%s:%d:%d",
			ft.sourceAddress.String(),
			ft.destinationAddress.String(),
			ft.sourcePort,
			ft.destinationPort,
		)
		return err
	}

	res.Body.Close() // nolint: errcheck

	pr.Error = ""
	pr.RTT = time.Since(startTime).String()
	pr.ApplicationListening = true
	pr.Type = gaia.PingProbeTypeResponse
	pr.FourTuple = fmt.Sprintf(
		"%s:%s:%d:%d",
		ft.destinationAddress.String(),
		ft.sourceAddress.String(),
		ft.destinationPort,
		ft.sourcePort,
	)

	if len(res.TLS.PeerCertificates) > 0 {
		pr.RemotePUID = res.TLS.PeerCertificates[0].Subject.CommonName
		pr.RemoteEndpointType = collector.EndPointTypePU
		if len(res.TLS.PeerCertificates[0].Subject.Organization) > 0 {
			pr.RemoteNamespace = res.TLS.PeerCertificates[0].Subject.Organization[0]
		}
		pr.PeerCertIssuer = res.TLS.PeerCertificates[0].Issuer.String()
		pr.PeerCertSubject = res.TLS.PeerCertificates[0].Subject.String()
		pr.PeerCertExpiry = res.TLS.PeerCertificates[0].NotAfter

		if found, controller := common.ExtractExtension(x509extensions.Controller(), res.TLS.PeerCertificates[0].Extensions); found {
			pr.RemoteController = string(controller)
		}
	}

	return nil
}

func dial(ctx context.Context, addr string, mark int) (net.Conn, error) {

	d := net.Dialer{
		Timeout: 5 * time.Second,
		Control: markedconn.ControlFunc(mark, false, nil),
	}
	return d.DialContext(ctx, "tcp", addr)
}
