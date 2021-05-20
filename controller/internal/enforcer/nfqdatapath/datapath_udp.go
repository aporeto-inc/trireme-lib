package nfqdatapath

// Go libraries
import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/tokens"
	markconstants "go.aporeto.io/enforcerd/trireme-lib/utils/constants"
	"go.uber.org/zap"
)

const (
	// Default retransmit delay for first packet
	retransmitDelay = 200
	// rentrasmitRetries is the number of times we will retry
	retransmitRetries = 3
	// ACLCheckMultipler is the multiplie on delay that is used to attempt and fallbackto acls
	ACLCheckMultipler = retransmitDelay * 12
)

// DropReason is used to indicate the drop reason for a packet
type DropReason string

// DropReason is the reason a packet is dropped and fin packets are generated
const (
	InvalidUDPState DropReason = "invalidUDPState"
	PolicyDrop      DropReason = "policyDrop"
)

var errHandshakePacket = errors.New("handshake packet")
var errDropQueuedPacket = errors.New("dropping queued packet")

func calculatedelay(retransmitDelay uint32, multiplier uint32) time.Duration {
	return time.Duration(retransmitDelay * (multiplier + 1))
}

// ProcessNetworkUDPPacket processes packets arriving from network and are destined to the application.
func (d *Datapath) ProcessNetworkUDPPacket(p *packet.Packet) (conn *connection.UDPConnection, err error) {

	if d.PacketLogsEnabled() {
		zap.L().Debug("Processing network packet ",
			zap.String("flow", p.L4FlowHash()),
		)
		defer zap.L().Debug("Finished Processing network packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.Error(err),
		)
	}
	udpPacketType := p.GetUDPType()

	switch udpPacketType {
	case packet.UDPSynMask:
		conn, err = d.netSynUDPRetrieveState(p)
		if err != nil {
			if d.PacketLogsEnabled() {
				zap.L().Debug("Packet rejected",
					zap.String("flow", p.L4FlowHash()),
					zap.Error(err),
				)
			}
			return nil, err
		}
	case packet.UDPSynAckMask, packet.UDPPolicyRejectMask:
		conn, err = d.netSynAckUDPRetrieveState(p)
		if err != nil {
			if d.PacketLogsEnabled() {
				zap.L().Debug("Syn ack Packet Rejected/ignored",
					zap.String("flow", p.L4FlowHash()),
				)
			}
			return nil, err
		}

	case packet.UDPFinAckMask:
		if err := d.processUDPFinPacket(p); err != nil {
			zap.L().Debug("unable to process udp fin ack",
				zap.String("flowhash", p.L4FlowHash()), zap.Error(err))
			return nil, err
		}
		// drop control packets
		return conn, fmt.Errorf("dropping udp fin ack control packet")

	default:
		// Process packets that don't have the control header. These are data packets.
		conn, err = d.netUDPAckRetrieveState(p)
		if err != nil {
			// Retrieve the context from the packet information.
			context, err := d.contextFromIP(false, p.Mark, p.DestPort(), packet.IPProtocolUDP)
			if err != nil {
				return nil, counters.CounterError(counters.ErrNonPUUDPTraffic, errNonPUUDPTraffic)
			}
			// Check if a network acl allows this traffic traffic coming from external network
			_, packetPolicy, err := context.NetworkACLPolicy(p)

			if err == nil && packetPolicy.Action.Accepted() {
				context.Counters().IncrementCounter(counters.ErrSynAckToExtNetAccept)
				if err = d.conntrack.UpdateApplicationFlowMark(
					p.SourceAddress(),
					p.DestinationAddress(),
					p.IPProto(),
					p.SourcePort(),
					p.DestPort(),
					markconstants.DefaultConnMark,
				); err != nil {
					zap.L().Error("Failed to update conntrack table for UDP flow at transmitter",
						zap.String("net-data-acl", p.L4FlowHash()),
						zap.Error(err),
					)

				}
				return conn, nil
			}

			if err := d.sendUDPFinPacket(p); err != nil {
				return nil, fmt.Errorf("net state not found, unable to send fin ack packets: %s", err)
			}
			if d.PacketLogsEnabled() {
				zap.L().Debug("No connection found for the flow, Dropping it",
					zap.String("flow", p.L4FlowHash()),
					zap.Error(err),
				)
			}
			return nil, err
		}
	}

	// We are processing only one connection at a time.
	conn.Lock()
	defer conn.Unlock()

	p.Print(packet.PacketStageIncoming, d.PacketLogsEnabled())

	if d.service != nil {
		if !d.service.PreProcessUDPNetPacket(p, conn.Context, conn) {
			p.Print(packet.PacketFailureService, d.PacketLogsEnabled())
			return conn, conn.Context.Counters().CounterError(counters.ErrUDPNetPreProcessingFailed, errors.New("pre  processing failed for network packet"))
		}
	}

	// handle handshake packets and do not deliver to application.
	action, claims, err := d.processNetUDPPacket(p, conn.Context, conn)
	if err != nil && err != errHandshakePacket && err != errDropQueuedPacket {
		zap.L().Debug("Rejecting packet because of policy decision",
			zap.String("flow", p.L4FlowHash()),
			zap.Error(err),
		)
		return conn, fmt.Errorf("packet processing failed for network packet: %s", err)
	}

	// Process the packet by any external services.
	if d.service != nil {
		if !d.service.PostProcessUDPNetPacket(p, action, claims, conn.Context, conn) {
			p.Print(packet.PacketFailureService, d.PacketLogsEnabled())
			return conn, conn.Context.Counters().CounterError(counters.ErrUDPNetPostProcessingFailed, errors.New("post service processing failed for network packet"))
		}
	}

	// If reached the final state, drain the queue.
	if conn.GetState() == connection.UDPClientSendAck {
		conn.SetState(connection.UDPData)
		for udpPacket := conn.ReadPacket(); udpPacket != nil; udpPacket = conn.ReadPacket() {
			if d.service != nil {
				// PostProcessServiceInterface
				// We call it for all outgoing packets.
				if !d.service.PostProcessUDPAppPacket(udpPacket, nil, conn.Context, conn) {
					udpPacket.Print(packet.PacketFailureService, d.PacketLogsEnabled())
					zap.L().Error("Failed to encrypt queued packet")
				}
			}

			err = d.ignoreFlow(udpPacket)
			if err != nil {
				zap.L().Error("Unable to ignore the flow", zap.Error(err))
			}

			err = d.writeUDPSocket(udpPacket.GetBuffer(0), udpPacket)
			if err != nil {
				zap.L().Error("Unable to transmit Queued UDP packets", zap.Error(err))
			}
		}
		return conn, fmt.Errorf("Drop the packet")
	}

	if conn.GetState() != connection.UDPData {
		// handshake packets are not to be delivered to application.

		return conn, errHandshakePacket

	}

	return conn, nil
}

func (d *Datapath) netSynUDPRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	// Retrieve the context from the packet information.
	context, err := d.contextFromIP(false, p.Mark, p.DestPort(), packet.IPProtocolUDP)
	if err != nil {
		return nil, counters.CounterError(counters.ErrNonPUTraffic, errNonPUTraffic)
	}

	// Check if a connection already exists for this flow. This can happen
	// in the case of retransmissions. If there is no connection, create
	// a new one.
	conn, cerr := d.udpNetOrigConnectionTracker.Get(p.L4FlowHash())
	if cerr != nil {
		conn := connection.NewUDPConnection(context, d.udpSocketWriter)
		conn.Secrets, conn.Auth.LocalDatapathPrivateKey, conn.Auth.LocalDatapathPublicKeyV1, conn.Auth.LocalDatapathPublicKeySignV1, conn.Auth.LocalDatapathPublicKeyV2, conn.Auth.LocalDatapathPublicKeySignV2 = context.GetSecrets()
		return conn, nil
	}
	return conn.(*connection.UDPConnection), nil
}

func (d *Datapath) netSynAckUDPRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {
	conn, err := d.udpSourcePortConnectionCache.GetReset(p.SourcePortHash(packet.PacketTypeNetwork), 0)
	if err != nil {
		return nil, counters.CounterError(counters.ErrUDPSynAckNoConnection, errors.New("No connection.Drop the syn ack packet"))
	}

	return conn.(*connection.UDPConnection), nil
}

func (d *Datapath) netUDPAckRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	hash := p.L4FlowHash()
	conn, err := d.udpNetReplyConnectionTracker.GetReset(hash, 0)
	if err != nil {
		conn, err = d.udpNetOrigConnectionTracker.GetReset(hash, 0)
		if err != nil {
			// This might be an existing udp connection.
			// Send FinAck to reauthorize the connection.

			return nil, fmt.Errorf("net state not found: %s", err)
		}
	}
	return conn.(*connection.UDPConnection), nil
}

// processNetUDPPacket processes a network UDP packet and dispatches it to different methods based on the flags.
// This applies only to control packets.
func (d *Datapath) processNetUDPPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	// Extra check, just in case the caller didn't provide a connection.
	if conn == nil {
		return nil, nil, fmt.Errorf("no connection provided")
	}

	udpPacketType := udpPacket.GetUDPType()

	// Update connection state in the internal state machine tracker
	switch udpPacketType {
	case packet.UDPSynMask:

		// Parse the packet for the identity information.
		action, claims, err = d.processNetworkUDPSynPacket(context, conn, udpPacket)
		if err != nil {
			if err = d.sendUDPRstPacket(udpPacket, conn); err != nil {
				zap.L().Error("Unable to send rst packet", zap.Error(err), zap.String("FlowHash", udpPacket.L4FlowHash()))
			}

			return nil, nil, err
		}
		// Send the return packet.
		if err = d.sendUDPSynAckPacket(udpPacket, context, conn); err != nil {
			return nil, nil, err
		}

		// Mark the state that we have transmitted a SynAck packet.
		conn.SetState(connection.UDPReceiverSendSynAck)
		return action, claims, errHandshakePacket

	case packet.UDPAckMask:
		// Retrieve the header and parse the signatures.
		if err = d.processNetworkUDPAckPacket(udpPacket, context, conn); err != nil {
			return nil, nil, err
		}

		// Set the connection to
		conn.SetState(connection.UDPReceiverProcessedAck)
		return nil, nil, errHandshakePacket

	case packet.UDPSynAckMask:
		// Process the synack header and claims of the other side.
		action, claims, err = d.processNetworkUDPSynAckPacket(udpPacket, context, conn)
		if err != nil {
			return nil, nil, err
		}
		// Send back the acknowledgement.
		err = d.sendUDPAckPacket(udpPacket, context, conn)
		if err != nil {
			return nil, nil, err
		}

		conn.SetState(connection.UDPClientSendAck)

		return action, claims, errHandshakePacket
	case packet.UDPPolicyRejectMask:

		if err := d.processUDPPolicyRstPacket(udpPacket, context, conn); err != nil {
			zap.L().Debug("unable to process udp policy rst",
				zap.String("flowhash", udpPacket.L4FlowHash()), zap.Error(err))
			return conn, nil, err
		}
		return conn, nil, fmt.Errorf("dropping udp rst control packet")
	default:
		state := conn.GetState()
		if state == connection.UDPReceiverProcessedAck || state == connection.UDPClientSendAck || state == connection.UDPData {
			conn.SetState(connection.UDPData)
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("invalid packet at state: %d", state)
	}
}

// ProcessApplicationUDPPacket processes packets arriving from an application and are destined to the network
func (d *Datapath) ProcessApplicationUDPPacket(p *packet.Packet) (conn *connection.UDPConnection, err error) {

	if d.PacketLogsEnabled() {
		zap.L().Debug("Processing application UDP packet ",
			zap.String("flow", p.L4FlowHash()),
		)
		defer zap.L().Debug("Finished Processing UDP application packet ",
			zap.String("flow", p.L4FlowHash()),
			zap.Error(err),
		)
	}
	// First retrieve the connection state.
	conn, err = d.appUDPRetrieveState(p)
	if err != nil {
		zap.L().Debug("Connection not found", zap.Error(err))
		return nil, counters.CounterError(counters.ErrNonPUTraffic, errNonPUTraffic)
	}

	// We are processing only one packet from a given connection at a time.
	conn.Lock()
	defer conn.Unlock()

	// do some pre processing.
	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessUDPAppPacket(p, conn.Context, conn, packet.UDPSynMask) {
			p.Print(packet.PacketFailureService, d.PacketLogsEnabled())
			return nil, conn.Context.Counters().CounterError(counters.ErrUDPAppPreProcessingFailed, errors.New("pre service processing failed for UDP application packet"))
		}
	}

	triggerControlProtocol := false
	switch conn.GetState() {
	case connection.UDPStart:
		// Queue the packet. We will send it after we authorize the session.
		if err = conn.QueuePackets(p); err != nil {
			// unable to queue packets, perhaps queue is full. if start
			// machine is still in start state, we can start authorisation
			// again. A drop counter is incremented.
			zap.L().Debug("udp queue full for connection", zap.String("flow", p.L4FlowHash()))
		}

		// Set the state indicating that we send out a Syn packet
		conn.SetState(connection.UDPClientSendSyn)
		// Drop the packet. We stored it in the queue.
		triggerControlProtocol = true

	case connection.UDPReceiverProcessedAck, connection.UDPClientSendAck, connection.UDPData:
		conn.SetState(connection.UDPData)

	default:
		if err = conn.QueuePackets(p); err != nil {
			return conn, conn.Context.Counters().CounterError(counters.ErrUDPDropQueueFull, fmt.Errorf("Unable to queue packets:%s", err))
		}
		return conn, conn.Context.Counters().CounterError(counters.ErrUDPDropInNfQueue, errDropQueuedPacket)
	}

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessUDPAppPacket(p, nil, conn.Context, conn) {
			p.Print(packet.PacketFailureService, d.PacketLogsEnabled())
			return conn, conn.Context.Counters().CounterError(counters.ErrUDPAppPostProcessingFailed, errors.New("Encryption failed for application packet"))
		}
	}

	if triggerControlProtocol {
		err = d.triggerNegotiation(p, conn.Context, conn)
		if err != nil {
			return conn, conn.Context.Counters().CounterError(counters.ErrUDPDropInNfQueue, errDropQueuedPacket)
		}
		return conn, errDropQueuedPacket
	}

	return conn, nil
}

func (d *Datapath) appUDPRetrieveState(p *packet.Packet) (*connection.UDPConnection, error) {

	hash := p.L4FlowHash()

	if conn, err := d.udpAppReplyConnectionTracker.GetReset(hash, 0); err == nil {
		return conn.(*connection.UDPConnection), nil
	}

	if conn, err := d.udpAppOrigConnectionTracker.GetReset(hash, 0); err == nil {
		return conn.(*connection.UDPConnection), nil
	}

	context, err := d.contextFromIP(true, p.Mark, p.SourcePort(), packet.IPProtocolUDP)
	if err != nil {
		return nil, counters.CounterError(counters.ErrNonPUTraffic, errors.New("No context in app processing"))
	}

	return connection.NewUDPConnection(context, d.udpSocketWriter), nil
}

// processApplicationUDPSynPacket processes a single Syn Packet
func (d *Datapath) triggerNegotiation(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {
	newPacket, err := d.clonePacketHeaders(udpPacket)
	if err != nil {
		return fmt.Errorf("Unable to clone packet: %s", err)
	}
	var udpData []byte
	conn.Secrets, conn.Auth.LocalDatapathPrivateKey, udpData = context.GetSynToken(nil, conn.Auth.Nonce, nil)
	udpOptions := packet.CreateUDPAuthMarker(packet.UDPSynMask, uint16(len(udpData)))
	// Attach the UDP data and token
	newPacket.UDPTokenAttach(udpOptions, udpData)
	if udpPacket.PlatformMetadata != nil {
		newPacket.PlatformMetadata = udpPacket.PlatformMetadata.Clone()
	}
	statusChannel := make(chan bool)

	go func() {
		// We started a handhsake drop reverse packets automatically
		// Assert connmark before relaseing packets if response is receied
		if err = d.conntrack.UpdateApplicationFlowMark(
			udpPacket.SourceAddress(),
			udpPacket.DestinationAddress(),
			udpPacket.IPProto(),
			udpPacket.SourcePort(),
			udpPacket.DestPort(),
			markconstants.HandshakeConnmark,
		); err != nil {
			zap.L().Error("Failed to update conntrack table for UDP flow at transmitter",
				zap.String("app-conn", udpPacket.L4FlowHash()),
				zap.String("state", fmt.Sprintf("%d", conn.GetState())),
				zap.Error(err),
			)

		}
	loop:
		for {
			select {
			case <-statusChannel:
				break loop
			case <-time.After(ACLCheckMultipler * time.Millisecond):
				return
			}
		}
		conn.Lock()
		defer conn.Unlock()
		if conn.GetState() == connection.UDPStart {
			// We did not receive any response from the remote.
			// It is most likely an external network lets evaluate acls at this point to see if we are allowed to talk to this ip
			report, pkt, perr := context.ApplicationACLPolicyFromAddr(udpPacket.DestinationAddress(), udpPacket.DestPort(), udpPacket.IPProto())
			if perr != nil && pkt.Action.Rejected() {
				d.reportExternalServiceFlow(context, report, pkt, true, udpPacket)
				return
			}
			<-time.After(50 * time.Millisecond) //Arbitrary number to ensure last handshake packet is dropped in our tables
			// Assert connmark before relaseing packets if response is receied
			if err = d.conntrack.UpdateApplicationFlowMark(
				udpPacket.SourceAddress(),
				udpPacket.DestinationAddress(),
				udpPacket.IPProto(),
				udpPacket.SourcePort(),
				udpPacket.DestPort(),
				markconstants.DefaultExternalConnMark,
			); err != nil {
				zap.L().Error("Failed to update conntrack table for UDP flow at transmitter",
					zap.String("app-conn", udpPacket.L4FlowHash()),
					zap.String("state", fmt.Sprintf("%d", conn.GetState())),
					zap.Error(err),
				)

			}
			for udpPacket := conn.ReadPacket(); udpPacket != nil; udpPacket = conn.ReadPacket() {
				if d.service != nil {
					// PostProcessServiceInterface
					// We call it for all outgoing packets.
					if !d.service.PostProcessUDPAppPacket(udpPacket, nil, conn.Context, conn) {
						udpPacket.Print(packet.PacketFailureService, d.PacketLogsEnabled())
						zap.L().Error("Failed to encrypt queued packet")
					}
				}

				err = d.ignoreFlow(udpPacket)
				if err != nil {
					zap.L().Error("Unable to ignore the flow", zap.Error(err))
				}

				err = d.writeUDPSocket(udpPacket.GetBuffer(0), udpPacket)
				if err != nil {
					zap.L().Error("Unable to transmit Queued UDP packets", zap.Error(err))
				}
			}
			conn.SetState(connection.UDPData)
			d.reportExternalServiceFlow(context, report, pkt, true, udpPacket)
			return
		}

	}()

	// send packet
	err = d.writeWithRetransmit(newPacket, conn, conn.SynChannel(), statusChannel)
	if err != nil {
		zap.L().Error("Unable to send syn token on raw socket", zap.Error(err), zap.Time("time", time.Now()))
		return fmt.Errorf("unable to transmit syn packet")
	}

	// Populate the caches to track the connection
	hash := udpPacket.L4FlowHash()
	d.udpAppOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.udpSourcePortConnectionCache.AddOrUpdate(newPacket.SourcePortHash(packet.PacketTypeApplication), conn)

	return nil

}

func (d *Datapath) writeWithRetransmit(udpPacket *packet.Packet, conn *connection.UDPConnection, stop chan bool, statusChan chan bool) error {
	buffer := udpPacket.GetBuffer(0)
	localBuffer := make([]byte, len(buffer))
	copy(localBuffer, buffer)
	zap.L().Debug("TRYINGT to send control packet", zap.String("FlowHash", udpPacket.L4FlowHash()))
	if err := d.writeUDPSocket(localBuffer, udpPacket); err != nil {
		zap.L().Error("Failed to write control packet to socket", zap.Error(err), zap.String("FlowHash", udpPacket.L4FlowHash()))
		return err
	}

	go func() {

		for retries := 0; retries < retransmitRetries; retries++ {
			delay := time.Millisecond * time.Duration((retransmitDelay * (retries + 1)))
			select {
			case <-stop:
				return
			case <-time.After(delay):
				if err := d.writeUDPSocket(localBuffer, udpPacket); err != nil {
					zap.L().Error("Failed to write control packet to socket", zap.Error(err), zap.String("FlowHash", udpPacket.L4FlowHash()))
				}
			}
		}
		// We did not get a synack maybe this dest is an external network
		if statusChan != nil {
			zap.L().Debug("Timedout should start acl")
			statusChan <- true
		}
		// retransmits did not succeed. Reset the state machine so that
		// next packet can try again.
		conn.SetState(connection.UDPStart)

	}()
	return nil
}

func (d *Datapath) clonePacketHeaders(p *packet.Packet) (*packet.Packet, error) {
	// copy the ip and udp headers.
	newSize := uint16(p.IPHeaderLen() + packet.UDPDataPos)
	newPacket := make([]byte, newSize)
	p.FixupIPHdrOnDataModify(p.IPTotalLen(), newSize)

	origBuffer := p.GetBuffer(0)
	_ = copy(newPacket, origBuffer[:newSize])

	return packet.New(packet.PacketTypeApplication, newPacket, p.Mark, true)
}

// sendUDPSynAckPacket processes a UDP SynAck packet
func (d *Datapath) sendUDPSynAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {

	claimsHeader := claimsheader.NewClaimsHeader()
	claims := &tokens.ConnectionClaims{
		CT:       context.CompressedTags(),
		LCL:      conn.Auth.Nonce[:],
		RMT:      conn.Auth.RemoteNonce,
		DEKV1:    conn.Auth.LocalDatapathPublicKeyV1,
		SDEKV1:   conn.Auth.LocalDatapathPublicKeySignV1,
		DEKV2:    conn.Auth.LocalDatapathPublicKeyV2,
		SDEKV2:   conn.Auth.LocalDatapathPublicKeySignV2,
		ID:       context.ManagementID(),
		RemoteID: conn.Auth.RemoteContextID,
	}

	var udpData []byte

	udpData, err = d.tokenAccessor.CreateSynAckPacketToken(conn.Auth.Proto314, claims, conn.EncodedBuf[:], conn.Auth.Nonce[:], claimsHeader, conn.Secrets, conn.Auth.SecretKey)
	if err != nil {
		return counters.CounterError(appUDPSynAckCounterFromError(err), err)
	}

	// Create UDP Option

	udpPacket.CreateReverseFlowPacket()

	// This for Windows and isn't necessary, but helps when driver is logging
	err = d.reverseFlow(udpPacket)
	if err != nil {
		return counters.CounterError(appUDPSynAckCounterFromError(err), err)
	}
	// Create UDP Option
	udpOptions := packet.CreateUDPAuthMarker(packet.UDPSynAckMask, uint16(len(udpData)))
	// Attach the UDP data and token
	udpPacket.UDPTokenAttach(udpOptions, udpData)

	// If we have already a backgroun re-transmit session, stop it at this point. We will
	// start from the beginning.
	if conn.GetState() == connection.UDPReceiverSendSynAck {
		conn.SynAckStop()
	}

	// Only start the retransmission timer once. Not on every packet.
	if err := d.writeWithRetransmit(udpPacket, conn, conn.SynAckChannel(), nil); err != nil {
		zap.L().Debug("Unable to send synack token on raw socket", zap.Error(err))
		return err
	}

	return nil
}

func (d *Datapath) sendUDPAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {
	// This for Windows and isn't necessary, but helps when driver is logging
	err = d.reverseFlow(udpPacket)
	if err != nil {
		return counters.CounterError(appUDPAckCounterFromError(err), err)
	}

	udpPacket.CreateReverseFlowPacket()

	claims := &tokens.ConnectionClaims{
		ID:       context.ManagementID(),
		RMT:      conn.Auth.RemoteNonce,
		RemoteID: conn.Auth.RemoteContextID,
	}

	udpData, err := d.tokenAccessor.CreateAckPacketToken(conn.Auth.Proto314, conn.Auth.SecretKey, claims, conn.EncodedBuf[:])
	if err != nil {
		return counters.CounterError(appUDPAckCounterFromError(err), err)
	}
	// Create UDP Option
	udpOptions := packet.CreateUDPAuthMarker(packet.UDPAckMask, uint16(len(udpData)))
	// Attach the UDP data and token
	udpPacket.UDPTokenAttach(udpOptions, udpData)

	// send packet
	err = d.writeUDPSocket(udpPacket.GetBuffer(0), udpPacket)
	if err != nil {
		return err
	}
	// We reached final state drain the queue here

	<-time.After(40 * time.Millisecond) //Arbitrary number give receiver chance to plumb conntrack
	for udpPacket := conn.ReadPacket(); udpPacket != nil; udpPacket = conn.ReadPacket() {
		if d.service != nil {
			// PostProcessServiceInterface
			// We call it for all outgoing packets.
			if !d.service.PostProcessUDPAppPacket(udpPacket, nil, conn.Context, conn) {
				udpPacket.Print(packet.PacketFailureService, d.PacketLogsEnabled())
				zap.L().Error("Failed to encrypt queued packet")
			}
		}

		err = d.ignoreFlow(udpPacket)
		if err != nil {
			zap.L().Error("Unable to ignore the flow", zap.Error(err))
		}

		err = d.writeUDPSocket(udpPacket.GetBuffer(0), udpPacket)
		if err != nil {
			zap.L().Error("Unable to transmit Queued UDP packets", zap.Error(err))
		}
	}

	// When server and client are the same machine, we can't ignore the
	// flow until the server side receives the Ack packet
	if !udpPacket.SourceAddress().Equal(udpPacket.DestinationAddress()) {
		if err := d.ignoreFlow(udpPacket); err != nil {
			zap.L().Error("Failed to ignore flow", zap.Error(err))
		}
	}
	if err = d.conntrack.UpdateApplicationFlowMark(
		udpPacket.SourceAddress(),
		udpPacket.DestinationAddress(),
		udpPacket.IPProto(),
		udpPacket.SourcePort(),
		udpPacket.DestPort(),
		markconstants.DefaultConnMark,
	); err != nil {
		zap.L().Error("Failed to update conntrack table for UDP flow at transmitter",
			zap.String("app-conn", udpPacket.L4FlowHash()),
			zap.String("state", fmt.Sprintf("%d", conn.GetState())),
			zap.Error(err),
		)
		return err
	}

	conn.SetState(connection.UDPData)
	zap.L().Debug("Clearing fin packet entry in cache", zap.String("flowhash", udpPacket.L4FlowHash()))
	if err := d.udpFinPacketTracker.Remove(udpPacket.L4FlowHash()); err != nil {
		zap.L().Debug("Unable to remove entry from udp finack cache")
	}
	return nil
}

// processNetworkUDPSynPacket processes a syn packet arriving from the network
func (d *Datapath) processNetworkUDPSynPacket(context *pucontext.PUContext, conn *connection.UDPConnection, udpPacket *packet.Packet) (action interface{}, claims *tokens.ConnectionClaims, err error) {

	rejected := false
	networkReport, pkt, perr := context.NetworkACLPolicy(udpPacket)
	if perr == nil {
		rejected = pkt.Action.Rejected()
		if rejected {
			perr = fmt.Errorf("rejected by ACL policy %s", pkt.PolicyID)
		}
	} else {
		// We got an error, but ensure it isn't the catch all policy
		if !(pkt != nil && pkt.Action.Rejected() && pkt.PolicyID == "default") {
			rejected = true
		}
	}

	if rejected {
		d.reportExternalServiceFlow(context, networkReport, pkt, false, udpPacket)
		return nil, nil, context.Counters().CounterError(counters.ErrUDPSynDroppedPolicy, fmt.Errorf("packet had identity: incoming connection dropped:due to reject acl %s", perr))
	}
	claims = &conn.Auth.ConnectionClaims
	secretKey, _, controller, remoteNonce, remoteContextID, proto314, err := d.tokenAccessor.ParsePacketToken(conn.Auth.LocalDatapathPrivateKey, udpPacket.ReadUDPToken(), conn.Secrets, claims, false)

	if err != nil {
		d.reportUDPRejectedFlow(udpPacket, conn, collector.DefaultEndPoint, context.ManagementID(), context, collector.InvalidToken, nil, nil, false)
		return nil, nil, conn.Context.Counters().CounterError(netUDPSynCounterFromError(err), fmt.Errorf("UDP Syn packet dropped because of invalid token: %s", err))
	}

	if controller != nil && !controller.SameController {
		conn.SourceController = controller.Controller
	}

	// Why is this required. Take a look.
	//txLabel, _ := claims.T.Get(enforcerconstants.TransmitterLabel)

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	tags := claims.T.Copy()
	tags.AppendKeyValue(constants.PortNumberLabelString, fmt.Sprintf("%s/%s", constants.UDPProtoString, strconv.Itoa(int(udpPacket.DestPort()))))

	// Add the controller to the claims
	if controller != nil && len(controller.Controller) > 0 {
		tags.AppendKeyValue(constants.ControllerLabelString, controller.Controller)
	}

	report, pkt := context.SearchRcvRules(tags)
	if pkt.Action.Rejected() {
		d.reportUDPRejectedFlow(udpPacket, conn, remoteContextID, context.ManagementID(), context, collector.PolicyDrop, report, pkt, false)
		return nil, nil, conn.Context.Counters().CounterError(counters.ErrUDPSynDroppedPolicy, fmt.Errorf("connection rejected because of policy: %s", claims.T.String()))
	}

	hash := udpPacket.L4FlowHash()

	// conntrack
	d.udpNetOrigConnectionTracker.AddOrUpdate(hash, conn)
	d.udpAppReplyConnectionTracker.AddOrUpdate(udpPacket.L4ReverseFlowHash(), conn)

	conn.Auth.SecretKey = secretKey
	conn.Auth.RemoteNonce = remoteNonce
	conn.Auth.RemoteContextID = remoteContextID
	conn.Auth.Proto314 = proto314

	// Record actions
	conn.ReportFlowPolicy = report
	conn.PacketFlowPolicy = pkt

	return pkt, claims, nil
}

func (d *Datapath) processNetworkUDPSynAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (action interface{}, claims *tokens.ConnectionClaims, err error) {
	conn.SynStop()
	claims = &conn.Auth.ConnectionClaims
	secretKey, _, controller, remoteNonce, remoteContextID, proto314, err := d.tokenAccessor.ParsePacketToken(conn.Auth.LocalDatapathPrivateKey, udpPacket.ReadUDPToken(), conn.Secrets, claims, true)
	if err != nil {
		d.reportUDPRejectedFlow(udpPacket, conn, context.ManagementID(), collector.DefaultEndPoint, context, collector.MissingToken, nil, nil, true)
		return nil, nil, conn.Context.Counters().CounterError(netUDPSynAckCounterFromError(err), errors.New("SynAck packet dropped because of bad claims"))
	}

	if controller != nil && !controller.SameController {
		conn.DestinationController = controller.Controller
	}
	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	tags := claims.T.Copy()
	tags.AppendKeyValue(constants.PortNumberLabelString, fmt.Sprintf("%s/%s", constants.UDPProtoString, strconv.Itoa(int(udpPacket.SourcePort()))))

	// Add the controller to the claims
	if controller != nil && len(controller.Controller) > 0 {
		tags.AppendKeyValue(constants.ControllerLabelString, controller.Controller)
	}

	report, pkt := context.SearchTxtRules(tags, !d.mutualAuthorization)
	if pkt.Action.Rejected() {
		d.reportUDPRejectedFlow(udpPacket, conn, remoteContextID, context.ManagementID(), context, collector.PolicyDrop, report, pkt, true)
		return nil, nil, conn.Context.Counters().CounterError(counters.ErrUDPSynAckPolicy, fmt.Errorf("dropping because of reject rule on transmitter: %s", claims.T.String()))
	}

	// conntrack
	d.udpNetReplyConnectionTracker.AddOrUpdate(udpPacket.L4FlowHash(), conn)
	conn.Auth.SecretKey = secretKey
	conn.Auth.RemoteNonce = remoteNonce
	conn.Auth.RemoteContextID = remoteContextID
	conn.Auth.Proto314 = proto314

	return pkt, claims, nil
}

func (d *Datapath) processNetworkUDPAckPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) {
	conn.SynAckStop()
	if err = d.tokenAccessor.ParseAckToken(conn.Auth.Proto314, conn.Auth.SecretKey, conn.Auth.Nonce[:], udpPacket.ReadUDPToken(), &conn.Auth.ConnectionClaims); err != nil {
		d.reportUDPRejectedFlow(udpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, collector.InvalidToken, conn.ReportFlowPolicy, conn.PacketFlowPolicy, false)
		return conn.Context.Counters().CounterError(netUDPAckCounterFromError(err), fmt.Errorf("ack packet dropped because signature validation failed: %s", err))
	}

	// For Windows, we allow the flow
	if err := d.setFlowState(udpPacket, true); err != nil {
		zap.L().Error("Failed to ignore flow", zap.Error(err))
	}

	// Plumb connmark rule here.
	if err := d.conntrack.UpdateNetworkFlowMark(
		udpPacket.SourceAddress(),
		udpPacket.DestinationAddress(),
		udpPacket.IPProto(),
		udpPacket.SourcePort(),
		udpPacket.DestPort(),
		markconstants.DefaultConnMark,
	); err != nil {
		zap.L().Error("Failed to update conntrack table after ack packet")
	}

	d.reportUDPAcceptedFlow(udpPacket, conn, conn.Auth.RemoteContextID, context.ManagementID(), context, conn.ReportFlowPolicy, conn.PacketFlowPolicy, false)

	conn.Context.Counters().IncrementCounter(counters.ErrUDPConnectionsProcessed)
	return nil
}

// sendUDPFinPacket sends a Fin packet to Peer.
func (d *Datapath) sendUDPFinPacket(udpPacket *packet.Packet) (err error) {
	// Create UDP Option
	udpOptions := packet.CreateUDPAuthMarker(packet.UDPFinAckMask, 0)
	udpPacket.CreateReverseFlowPacket()

	err = d.reverseFlow(udpPacket)
	if err != nil {

		return counters.CounterError(counters.ErrUDPDropFin, err)
	}
	// Attach the UDP data and token
	udpPacket.UDPTokenAttach(udpOptions, []byte{})

	// no need for retransmits here.
	err = d.writeUDPSocket(udpPacket.GetBuffer(0), udpPacket)
	if err != nil {
		zap.L().Debug("Unable to send fin packet on raw socket:", zap.Error(err))
		return counters.CounterError(counters.ErrUDPDropFin, fmt.Errorf("Unable to send fin packet on raw socket: %s", err.Error()))
	}

	return nil
}

// sendUDPRstPacket sends a rst packet to Peer.
func (d *Datapath) sendUDPRstPacket(udpPacket *packet.Packet, conn *connection.UDPConnection) (err error) {
	// Create UDP Option
	udpOptions := packet.CreateUDPAuthMarker(packet.UDPPolicyRejectMask, 0)
	udpPacket.CreateReverseFlowPacket()
	// TODO ::: Have a signed payload this packets will force remote end to process acls
	// So we have to be sure someone we trust send this
	err = d.reverseFlow(udpPacket)
	if err != nil {
		return conn.Context.Counters().CounterError(counters.ErrUDPDropRst, err)
	}

	// Attach the UDP data and token
	udpPacket.UDPTokenAttach(udpOptions, []byte{})

	// For Windows, this mark udpPacket packet so that when writeUDPSocket is called,
	// it will send the packet but will drop additional packets for this flow.
	if err := d.dropFlow(udpPacket); err != nil {
		zap.L().Error("Failed to drop flow", zap.Error(err))
	}

	// no need for retransmits here.
	err = d.writeUDPSocket(udpPacket.GetBuffer(0), udpPacket)
	if err != nil {
		zap.L().Debug("Unable to send fin packet on raw socket", zap.Error(err))
		return conn.Context.Counters().CounterError(counters.ErrUDPDropRst, fmt.Errorf("Unable to send rst packet on raw socket: %s", err.Error()))
	}

	// conn.SynStop()
	// conn.SynAckStop()
	// Plumb connmark rule here. drop packet on this flow. Till we see a acceptable handshake packet again
	if err := d.conntrack.UpdateNetworkFlowMark(
		udpPacket.SourceAddress(),
		udpPacket.DestinationAddress(),
		udpPacket.IPProto(),
		udpPacket.SourcePort(),
		udpPacket.DestPort(),
		markconstants.DropConnmark,
	); err != nil {
		zap.L().Error("Failed to update conntrack table after ack packet")
	}
	return nil
}

func (d *Datapath) processUDPPolicyRstPacket(udpPacket *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) (err error) { // nolint
	conn.SetState(connection.UDPRST)
	conn.SynStop()
	conn.SynAckStop()
	if err := d.udpAppOrigConnectionTracker.Remove(udpPacket.L4ReverseFlowHash()); err != nil {
		zap.L().Debug("Failed to clean cache udpappOrigConnectionTracker", zap.Error(err))
	}
	if err := d.udpSourcePortConnectionCache.Remove(udpPacket.SourcePortHash(packet.PacketTypeNetwork)); err != nil {
		zap.L().Debug("Failed to clean cache udpsourcePortConnectionCache", zap.Error(err))
	}
	if err := d.setFlowState(udpPacket, false); err != nil {
		zap.L().Error("Failed to drop flow", zap.Error(err))
	}
	if err := d.conntrack.UpdateNetworkFlowMark(
		udpPacket.SourceAddress(),
		udpPacket.DestinationAddress(),
		udpPacket.IPProto(),
		udpPacket.SourcePort(),
		udpPacket.DestPort(),
		markconstants.DropConnmark,
	); err != nil {
		zap.L().Error("Failed to update conntrack table after ack packet")
	}
	return nil
}

// Update the udp fin cache and delete the connmark.
func (d *Datapath) processUDPFinPacket(udpPacket *packet.Packet) (err error) { // nolint

	// add it to the udp fin cache. If we have already received the fin packet
	// for this flow. There is no need to change the connmark label again.
	if d.udpFinPacketTracker.AddOrUpdate(udpPacket.L4ReverseFlowHash(), true) {
		return nil
	}

	// clear cache entries.
	if err := d.udpAppOrigConnectionTracker.Remove(udpPacket.L4ReverseFlowHash()); err != nil {
		zap.L().Debug("Failed to clean cache udpappOrigConnectionTracker", zap.Error(err))
	}
	if err := d.udpSourcePortConnectionCache.Remove(udpPacket.SourcePortHash(packet.PacketTypeNetwork)); err != nil {
		zap.L().Debug("Failed to clean cache udpsourcePortConnectionCache", zap.Error(err))
	}
	if err := d.setFlowState(udpPacket, false); err != nil {
		zap.L().Error("Failed to drop flow", zap.Error(err))
	}
	if err = d.conntrack.UpdateNetworkFlowMark(
		udpPacket.SourceAddress(),
		udpPacket.DestinationAddress(),
		udpPacket.IPProto(),
		udpPacket.SourcePort(),
		udpPacket.DestPort(),
		markconstants.DeleteConnmark,
	); err != nil {
		zap.L().Error("Failed to update conntrack table for flow to terminate connection",
			zap.String("app-conn", udpPacket.L4FlowHash()),
			zap.Error(err),
		)
	}

	return nil
}

// note: for platforms that need it (Windows), please ensure that udpPacket.PlatformMetadata is set.
// thus, for any Packets created outside of the driver packet callback, the originating metadata must be
// propagated to the udpPacket argument before this call.
func (d *Datapath) writeUDPSocket(buf []byte, udpPacket *packet.Packet) error {
	return d.udpSocketWriter.WriteSocket(buf, udpPacket.IPversion(), udpPacket.PlatformMetadata)
}
