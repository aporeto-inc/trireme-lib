package nfqdatapath

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/ghedo/go.pkt/packet/raw"
	"github.com/ghedo/go.pkt/packet/tcp"
	"github.com/ghedo/go.pkt/routing"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	enforcerconstants "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	tpacket "go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pingconfig"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/tokens"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/gaia"
	"go.uber.org/zap"
)

var (
	// For unit tests.
	srcip          = getSrcIP
	dial           = dialIP
	bind           = bindRandomPort
	close          = closeRandomPort
	randUint32     = rand.Uint32
	since          = time.Since
	isAppListening = isAppListeningInPort

	removeDelay = 10 * time.Second
	synAckDelay = 3 * time.Second

	_ io.Writer = &pingConn{}
)

func (d *Datapath) initiatePingHandshake(_ context.Context, context *pucontext.PUContext, pingConfig *policy.PingConfig) error {

	zap.L().Debug("Initiating ping (syn)")

	srcIP, err := srcip(pingConfig.IP)
	if err != nil {
		return fmt.Errorf("unable to get source ip: %v", err)
	}

	conn, err := dial(srcIP, pingConfig.IP)
	if err != nil {
		return fmt.Errorf("unable to dial on app syn: %v", err)
	}
	defer conn.Close() // nolint: errcheck

	for i := 0; i < pingConfig.Iterations; i++ {
		if err := d.sendSynPacket(context, pingConfig, conn, srcIP, i); err != nil {
			return err
		}
	}

	return nil
}

// sendSynPacket sends tcp syn packet to the socket. It also dispatches a report.
func (d *Datapath) sendSynPacket(context *pucontext.PUContext, pingConfig *policy.PingConfig, conn PingConn, srcIP net.IP, iterationID int) error {

	tcpConn := connection.NewTCPConnection(context, nil)
	tcpConn.PingConfig = pingconfig.New()

	srcPort, err := bind(tcpConn)
	if err != nil {
		return fmt.Errorf("unable to bind free source port: %v", err)
	}

	claimsHeader := claimsheader.NewClaimsHeader(
		claimsheader.OptionPing(true),
	)

	pingPayload := &policy.PingPayload{
		PingID:        pingConfig.ID,
		IterationID:   iterationID,
		NamespaceHash: context.ManagementNamespaceHash(),
	}

	var tcpData []byte
	tcpConn.Secrets, tcpConn.Auth.LocalDatapathPrivateKey, tcpData = context.GetSynToken(pingPayload, tcpConn.Auth.Nonce, claimsHeader)

	seqNum := randUint32()
	p, err := constructTCPPacket(conn, srcIP, pingConfig.IP, srcPort, pingConfig.Port, seqNum, 0, tcp.Syn, tcpData)
	if err != nil {
		return fmt.Errorf("unable to construct syn packet: %v", err)
	}

	// We always get a default policy.
	_, pkt, _ := context.ApplicationACLPolicyFromAddr(pingConfig.IP, pingConfig.Port, packet.IPProtocolTCP)

	pingErr := "timeout"
	if e := pingConfig.Error(); e != "" {
		pingErr = e
	}

	// RequestTimeout report cached in the connection. This will be sent on
	// expiration timeout for this connection.
	tcpConn.PingConfig.SetPingReport(&collector.PingReport{
		PingID:          pingConfig.ID,
		IterationID:     iterationID,
		AgentVersion:    d.agentVersion.String(),
		PayloadSize:     len(tcpData),
		PayloadSizeType: gaia.PingProbePayloadSizeTypeTransmitted,
		Type:            gaia.PingProbeTypeRequest,
		Error:           pingErr,
		PUID:            context.ManagementID(),
		Namespace:       context.ManagementNamespace(),
		Protocol:        tpacket.IPProtocolTCP,
		ServiceType:     "L3",
		FourTuple: flowTuple(
			tpacket.PacketTypeApplication,
			srcIP,
			pingConfig.IP,
			srcPort,
			pingConfig.Port,
		),
		SeqNum:              seqNum,
		TargetTCPNetworks:   pingConfig.TargetTCPNetworks,
		ExcludedNetworks:    pingConfig.ExcludedNetworks,
		RemoteNamespaceType: gaia.PingProbeRemoteNamespaceTypeHash,
		Claims:              context.Identity().GetSlice(),
		ClaimsType:          gaia.PingProbeClaimsTypeTransmitted,
		ACLPolicyID:         pkt.PolicyID,
		ACLPolicyAction:     pkt.Action,
	})
	tcpConn.TCPtuple = &connection.TCPTuple{
		SourceAddress:      srcIP,
		DestinationAddress: pingConfig.IP,
		SourcePort:         srcPort,
		DestinationPort:    pingConfig.Port,
	}
	tcpConn.PingConfig.StartTime = time.Now()
	tcpConn.PingConfig.SetPingID(pingConfig.ID)
	tcpConn.PingConfig.SetIterationID(iterationID)
	tcpConn.PingConfig.SetSeqNum(seqNum)
	tcpConn.SetState(connection.TCPSynSend)
	key := flowTuple(tpacket.PacketTypeApplication, srcIP, pingConfig.IP, srcPort, pingConfig.Port)

	d.cachePut(d.tcpClient, key, tcpConn)

	if _, err := conn.Write(p); err != nil {
		return fmt.Errorf("unable to send syn packet: %v", err)
	}

	return nil
}

// processPingNetSynPacket should only be called when the packet is recognized as a ping syn packet.
func (d *Datapath) processPingNetSynPacket(
	context *pucontext.PUContext,
	tcpConn *connection.TCPConnection,
	tcpPacket *tpacket.Packet,
	payloadSize int,
	pkt *policy.FlowPolicy,
	claims *tokens.ConnectionClaims,
) error {
	zap.L().Debug("Processing ping network syn packet", zap.String("conn", tcpPacket.L4FlowHash()))

	if tcpConn.GetState() == connection.TCPSynReceived || tcpConn.GetState() == connection.TCPSynAckSend {
		zap.L().Debug("Dropping duplicate ping syn packets")
		return errDropPingNetSyn
	}

	defer func() {
		tcpConn.SetState(connection.TCPSynReceived)
		tcpConn.PingConfig.SetSocketClosed(true)
		tcpConn.PingConfig.SetPingID(claims.P.PingID)
		tcpConn.PingConfig.SetIterationID(claims.P.IterationID)

		txtID, ok := claims.T.Get(enforcerconstants.TransmitterLabel)
		if !ok {
			zap.L().Warn("missing transmitter label")
		}

		d.cachePut(d.tcpServer, tcpPacket.L4FlowHash(), tcpConn)
		d.sendRequestRecvReport(txtID, claims.P, tcpPacket, context, pkt, payloadSize, tcpConn.SourceController)
	}()

	if tcpConn.PingConfig == nil {
		tcpConn.PingConfig = pingconfig.New()
	}

	listening, err := isAppListening(tcpPacket.DestPort())
	if listening && !pkt.Action.Rejected() {
		zap.L().Debug("Appplication listening", zap.String("conn", tcpPacket.L4FlowHash()), zap.Error(err))

		time.AfterFunc(synAckDelay, func() {

			if tcpConn.PingConfig.ApplicationListening() {
				return
			}

			if err := d.sendSynAckPacket(context, tcpConn, tcpPacket, claims); err != nil {
				zap.L().Error("unable to send synack paket", zap.Error(err))
			}
		})

		return nil
	}

	if err := d.sendSynAckPacket(context, tcpConn, tcpPacket, claims); err != nil {
		return err
	}

	return errDropPingNetSyn
}

func (d *Datapath) sendSynAckPacket(
	context *pucontext.PUContext,
	tcpConn *connection.TCPConnection,
	tcpPacket *tpacket.Packet,
	claims *tokens.ConnectionClaims,
) error {

	claimsHeader := claimsheader.NewClaimsHeader(
		claimsheader.OptionPing(true),
	)

	pingPayload := &policy.PingPayload{
		PingID:        claims.P.PingID,
		IterationID:   claims.P.IterationID,
		NamespaceHash: context.ManagementNamespaceHash(),
	}

	claimsNew := &tokens.ConnectionClaims{
		CT:       context.CompressedTags(),
		LCL:      tcpConn.Auth.Nonce[:],
		RMT:      tcpConn.Auth.RemoteNonce,
		DEKV1:    tcpConn.Auth.LocalDatapathPublicKeyV1,
		SDEKV1:   tcpConn.Auth.LocalDatapathPublicKeySignV1,
		DEKV2:    tcpConn.Auth.LocalDatapathPublicKeyV2,
		SDEKV2:   tcpConn.Auth.LocalDatapathPublicKeySignV2,
		ID:       context.ManagementID(),
		RemoteID: tcpConn.Auth.RemoteContextID,
		P:        pingPayload,
	}

	tcpData, err := d.tokenAccessor.CreateSynAckPacketToken(tcpConn.Auth.Proto314, claimsNew, tcpConn.EncodedBuf[:], tcpConn.Auth.Nonce[:], claimsHeader, tcpConn.Secrets, tcpConn.Auth.SecretKey) //nolint
	if err != nil {
		return fmt.Errorf("unable to create ping synack token: %w", err)
	}

	conn, err := dial(tcpPacket.DestinationAddress(), tcpPacket.SourceAddress())
	if err != nil {
		return fmt.Errorf("unable to construct synack packet %w", err)
	}
	defer conn.Close() // nolint: errcheck

	p, err := constructTCPPacket(
		conn,
		tcpPacket.DestinationAddress(),
		tcpPacket.SourceAddress(),
		tcpPacket.DestPort(),
		tcpPacket.SourcePort(),
		randUint32(),
		tcpPacket.TCPSeqNum()+1,
		tcp.Syn|tcp.Ack,
		tcpData,
	)
	if err != nil {
		return fmt.Errorf("unable to construct synack packet: %w", err)
	}

	if _, err := conn.Write(p); err != nil {
		return fmt.Errorf("unable to send synack packet: %w", err)
	}

	tcpConn.SetState(connection.TCPSynAckSend)

	return nil
}

// processPingNetSynAckPacket should only be called when the packet is recognized as a ping synack packet.
func (d *Datapath) processPingNetSynAckPacket(
	context *pucontext.PUContext,
	tcpConn *connection.TCPConnection,
	tcpPacket *tpacket.Packet,
	payloadSize int,
	pkt *policy.FlowPolicy,
	claims *tokens.ConnectionClaims,
	ext bool,
) error {
	zap.L().Debug("Processing ping network synack packet",
		zap.Bool("externalNetwork", ext),
		zap.String("conn", tcpPacket.SourcePortHash(packet.PacketTypeNetwork)),
	)

	if tcpConn.PingConfig == nil {
		return errDropPingNetSynAck
	}

	receiveTime := since(tcpConn.PingConfig.StartTime).String()

	defer func() {
		tcpConn.SetState(connection.TCPSynAckReceived)

		if !tcpConn.PingConfig.SocketClosed() {
			defer func() {
				if err := close(tcpConn); err != nil {
					zap.L().Warn("unable to close socket", zap.Reflect("fd", tcpConn.PingConfig.SocketFd()), zap.Error(err))
				}
			}()
		}

		time.AfterFunc(removeDelay, func() {
			d.cacheRemove(d.tcpClient, tcpPacket.SourcePortHash(packet.PacketTypeNetwork))
		})

		if err := respondWithRstPacket(tcpPacket, nil); err != nil {
			zap.L().Warn("unable to send rst packet", zap.Error(err))
		}
	}()

	// Drop duplicate synack packets.
	if tcpConn.GetState() == connection.TCPSynAckReceived {
		return errDropPingNetSynAck
	}

	// Synack from externalnetwork.
	if ext {
		d.sendExtResponseRecvReport(
			context,
			receiveTime,
			pkt,
			payloadSize,
			tcpConn,
		)
		return errDropPingNetSynAck
	}

	txtID, ok := claims.T.Get(enforcerconstants.TransmitterLabel)
	if !ok {
		return fmt.Errorf("missing transmitter label")
	}

	d.sendResponseRecvReport(
		txtID,
		claims.P,
		context,
		receiveTime,
		pkt,
		payloadSize,
		tcpConn,
		tcpConn.DestinationController,
	)

	return errDropPingNetSynAck
}

// respondWithRstPacket sends a rst packet in response to tcpPacket.
func respondWithRstPacket(tcpPacket *tpacket.Packet, payload []byte) error {

	conn, err := dial(tcpPacket.DestinationAddress(), tcpPacket.SourceAddress())
	if err != nil {
		return fmt.Errorf("unable to dial: %w", err)
	}
	defer conn.Close() // nolint: errcheck

	p, err := constructTCPPacket(
		conn,
		tcpPacket.DestinationAddress(),
		tcpPacket.SourceAddress(),
		tcpPacket.DestPort(),
		tcpPacket.SourcePort(),
		tcpPacket.TCPAckNum(),
		tcpPacket.TCPSeqNum()+1,
		tcp.Rst,
		payload,
	)
	if err != nil {
		return fmt.Errorf("unable to construct rst packet: %w", err)
	}

	if _, err := conn.Write(p); err != nil {
		return fmt.Errorf("unable to send rst packet: %w", err)
	}

	return nil
}

// sendRequestRecvReport sends a report on syn recv state.
func (d *Datapath) sendRequestRecvReport(
	srcPUID string,
	pingPayload *policy.PingPayload,
	tcpPacket *tpacket.Packet,
	context *pucontext.PUContext,
	pkt *policy.FlowPolicy,
	payloadSize int,
	controller string,
) {

	err := ""
	if pkt.Action.Rejected() {
		err = collector.PolicyDrop
	}

	d.sendPingReport(
		pingPayload.PingID,
		pingPayload.IterationID,
		d.agentVersion.String(),
		tcpPacket.L4FlowHash(),
		"",
		srcPUID,
		context.ManagementID(),
		context.ManagementNamespace(),
		pingPayload.NamespaceHash,
		gaia.PingProbeTypeRequest,
		payloadSize,
		pkt.PolicyID,
		pkt.Action,
		false,
		collector.EndPointTypePU,
		tcpPacket.TCPSeqNum(),
		controller,
		true,
		false,
		context.Identity().GetSlice(),
		"",
		policy.ActionType(0),
		true,
		err,
	)
}

// sendResponseRecvReport sends a report on synack recv state.
func (d *Datapath) sendResponseRecvReport(
	srcPUID string,
	pingPayload *policy.PingPayload,
	context *pucontext.PUContext,
	rtt string,
	pkt *policy.FlowPolicy,
	payloadSize int,
	tcpConn *connection.TCPConnection,
	controller string,
) {

	pingErr := ""
	if !tcpConn.PingConfig.PingReport().TargetTCPNetworks {
		pingErr = policy.ErrTargetTCPNetworks
	}

	if tcpConn.PingConfig.PingReport().ExcludedNetworks {
		pingErr = policy.ErrExcludedNetworks
	}

	if pkt.Action.Rejected() {
		pingErr = collector.PolicyDrop
	}

	d.sendPingReport(
		pingPayload.PingID,
		pingPayload.IterationID,
		d.agentVersion.String(),
		flowTuple(
			tpacket.PacketTypeNetwork,
			tcpConn.TCPtuple.SourceAddress,
			tcpConn.TCPtuple.DestinationAddress,
			tcpConn.TCPtuple.SourcePort,
			tcpConn.TCPtuple.DestinationPort,
		),
		rtt,
		srcPUID,
		context.ManagementID(),
		context.ManagementNamespace(),
		pingPayload.NamespaceHash,
		gaia.PingProbeTypeResponse,
		payloadSize,
		pkt.PolicyID,
		pkt.Action,
		pingPayload.ApplicationListening,
		collector.EndPointTypePU,
		tcpConn.PingConfig.SeqNum(),
		controller,
		tcpConn.PingConfig.PingReport().TargetTCPNetworks,
		tcpConn.PingConfig.PingReport().ExcludedNetworks,
		tcpConn.PingConfig.PingReport().Claims,
		tcpConn.PingConfig.PingReport().ACLPolicyID,
		tcpConn.PingConfig.PingReport().ACLPolicyAction,
		false,
		pingErr,
	)
}

// sendExtResponseRecvReport sends a report on synack from ext net.
func (d *Datapath) sendExtResponseRecvReport(
	context *pucontext.PUContext,
	rtt string,
	pkt *policy.FlowPolicy,
	payloadSize int,
	tcpConn *connection.TCPConnection,
) {
	d.sendPingReport(
		tcpConn.PingConfig.PingID(),
		tcpConn.PingConfig.IterationID(),
		d.agentVersion.String(),
		flowTuple(
			tpacket.PacketTypeNetwork,
			tcpConn.TCPtuple.SourceAddress,
			tcpConn.TCPtuple.DestinationAddress,
			tcpConn.TCPtuple.SourcePort,
			tcpConn.TCPtuple.DestinationPort,
		),
		rtt,
		"",
		context.ManagementID(),
		context.ManagementNamespace(),
		"",
		gaia.PingProbeTypeResponse,
		payloadSize,
		pkt.PolicyID,
		pkt.Action,
		true,
		collector.EndPointTypeExternalIP,
		tcpConn.PingConfig.SeqNum(),
		"",
		tcpConn.PingConfig.PingReport().TargetTCPNetworks,
		tcpConn.PingConfig.PingReport().ExcludedNetworks,
		tcpConn.PingConfig.PingReport().Claims,
		tcpConn.PingConfig.PingReport().ACLPolicyID,
		tcpConn.PingConfig.PingReport().ACLPolicyAction,
		false,
		"",
	)
}

func (d *Datapath) sendPingReport(
	pingID string,
	iterationID int,
	agentVersion,
	fourTuple,
	rtt,
	remoteID,
	puid,
	ns string,
	nsHash string,
	ptype gaia.PingProbeTypeValue,
	payloadSize int,
	policyID string,
	policyAction policy.ActionType,
	appListening bool,
	txType collector.EndPointType,
	seqNum uint32,
	controller string,
	tn,
	en bool,
	claims []string,
	aclPolicyID string,
	aclPolicyAction policy.ActionType,
	isServer bool,
	err string,
) {

	report := &collector.PingReport{
		PingID:               pingID,
		IterationID:          iterationID,
		AgentVersion:         agentVersion,
		FourTuple:            fourTuple,
		RTT:                  rtt,
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		Type:                 ptype,
		PUID:                 puid,
		RemotePUID:           remoteID,
		Namespace:            ns,
		RemoteNamespace:      nsHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		Protocol:             tpacket.IPProtocolTCP,
		ServiceType:          "L3",
		PolicyID:             policyID,
		PolicyAction:         policyAction,
		ApplicationListening: appListening,
		RemoteEndpointType:   txType,
		SeqNum:               seqNum,
		RemoteController:     controller,
		TargetTCPNetworks:    tn,
		ExcludedNetworks:     en,
		Claims:               claims,
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		ACLPolicyID:          aclPolicyID,
		ACLPolicyAction:      aclPolicyAction,
		IsServer:             isServer,
		Error:                err,
	}

	d.collector.CollectPingEvent(report)
}

// constructTCPPacket constructs a valid tcp packet that can be sent on wire.
func constructTCPPacket(conn PingConn, srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum, ackNum uint32, flag tcp.Flags, tcpData []byte) ([]byte, error) {

	// tcp.
	tcpPacket := tcp.Make()
	tcpPacket.SrcPort = srcPort
	tcpPacket.DstPort = dstPort
	tcpPacket.Flags = flag
	tcpPacket.Seq = seqNum
	tcpPacket.Ack = ackNum
	tcpPacket.WindowSize = 0xAAAA
	tcpPacket.Options = []tcp.Option{
		{
			Type: tcp.MSS,
			Len:  4,
			Data: []byte{0x05, 0x8C},
		},
	}
	tcpPacket.DataOff = uint8(6) // 5 (header size) + 1 * (4 byte options)

	if len(tcpData) != 0 {
		tcpPacket.Options = append(
			tcpPacket.Options,
			tcp.Option{
				Type: 34, // tfo
				Len:  enforcerconstants.TCPAuthenticationOptionBaseLen,
				Data: make([]byte, 2),
			},
		)
		tcpPacket.DataOff += uint8(1) // 6 + 1 * (4 byte options)
	}

	// payload.
	payload := raw.Make()
	payload.Data = tcpData

	// construct the wire packet
	buf, err := conn.ConstructWirePacket(srcIP, dstIP, tcpPacket, payload)
	if err != nil {
		return nil, fmt.Errorf("unable to encode packet to wire format: %v", err)
	}

	return buf, nil
}

// getSrcIP returns the interface ip that can reach the destination.
func getSrcIP(dstIP net.IP) (net.IP, error) {

	route, err := routing.RouteTo(dstIP)
	if err != nil || route == nil {
		return nil, fmt.Errorf("no route found for destination %s: %v", dstIP.String(), err)
	}

	ip, err := route.GetIfaceIPv4Addr()
	if err != nil {
		return nil, fmt.Errorf("unable to get interface ip address: %v", err)
	}

	return ip, nil
}

// flowTuple returns the tuple based on the stage in format <sip:dip:spt:dpt> or <dip:sip:dpt:spt>
func flowTuple(stage uint64, srcIP, dstIP net.IP, srcPort, dstPort uint16) string {

	if stage == tpacket.PacketTypeNetwork {
		return fmt.Sprintf("%s:%s:%s:%s", dstIP.String(), srcIP.String(), strconv.Itoa(int(dstPort)), strconv.Itoa(int(srcPort)))
	}

	return fmt.Sprintf("%s:%s:%s:%s", srcIP.String(), dstIP.String(), strconv.Itoa(int(srcPort)), strconv.Itoa(int(dstPort)))
}

// isAppListeningInPort returns true if the port is in use by IPv4:TCP app.
// It immediately closes the listener socket.
// Also returns the actual error for further scrutiny.
func isAppListeningInPort(port uint16) (bool, error) {

	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp4", addr)
	if listener != nil {
		listener.Close() // nolint:errcheck
	}

	return isAddressInUse(err), err
}

// isAddressInUse returns true for and unix.EADDRINUSE or windows.WSAEADDRINUSE errors.
func isAddressInUse(err error) bool {

	opErr, ok := err.(*net.OpError)
	if !ok {
		return false
	}

	syscallErr, ok := opErr.Unwrap().(*os.SyscallError)
	if !ok {
		return false
	}

	errNo, ok := syscallErr.Unwrap().(syscall.Errno)
	if !ok {
		return false
	}

	return isAddrInUseErrno(errNo)
}
