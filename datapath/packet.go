package datapath

// Go libraries
import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme/datapath/netfilter"
	"github.com/aporeto-inc/trireme/datapath/packet"
	"github.com/aporeto-inc/trireme/datapath/tokens"
	"github.com/aporeto-inc/trireme/eventlog"
	"github.com/golang/glog"
)

const (
	// TCPAuthenticationOptionBaseLen specifies the length of base TCP Authentication Option packet
	TCPAuthenticationOptionBaseLen = 4
	// TCPAuthenticationOptionAckLen specifies the length of TCP Authentication Option in the ack packet
	TCPAuthenticationOptionAckLen = 20

	// PortNumberLabelString is the label to use for port numbers
	PortNumberLabelString = "@port"
)

// processNetworkPacketsFromNFQ processes packets arriving from the network in an NF queue
func (d *DataPath) processNetworkPacketsFromNFQ(p *netfilter.NFPacket) *netfilter.Verdict {

	d.net.IncomingPackets++

	// Parse the packet - drop if parsing fails
	tcpPacket, err := packet.New(packet.PacketTypeNetwork, p.Buffer)
	if err != nil {
		d.net.CreateDropPackets++
		tcpPacket.Print(packet.PacketFailureCreate)
	} else {
		err = d.processNetworkPackets(tcpPacket)
	}

	if err != nil {
		return &netfilter.Verdict{
			V:       netfilter.NfDrop,
			Buffer:  tcpPacket.Buffer,
			Payload: nil,
			Options: nil,
		}
	}

	// Accept the packet
	return &netfilter.Verdict{
		V:       netfilter.NfAccept,
		Buffer:  tcpPacket.Buffer,
		Payload: tcpPacket.GetTCPData(),
		Options: tcpPacket.GetTCPOptions(),
	}
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *DataPath) processApplicationPacketsFromNFQ(p *netfilter.NFPacket) *netfilter.Verdict {

	d.app.IncomingPackets++
	// Being liberal on what we transmit - malformed TCP packets are let go
	// We are strict on what we accept on the other side, but we don't block
	// lots of things at the ingress to the network
	tcpPacket, err := packet.New(packet.PacketTypeApplication, p.Buffer)
	if err != nil {
		d.app.CreateDropPackets++
		tcpPacket.Print(packet.PacketFailureCreate)
	} else {
		err = d.processApplicationPackets(tcpPacket)
	}

	if err != nil {
		return &netfilter.Verdict{
			V:       netfilter.NfDrop,
			Buffer:  tcpPacket.Buffer,
			Payload: nil,
			Options: nil,
		}
	}

	// Accept the packet
	return &netfilter.Verdict{
		V:       netfilter.NfAccept,
		Buffer:  tcpPacket.Buffer,
		Payload: tcpPacket.GetTCPData(),
		Options: tcpPacket.GetTCPOptions(),
	}
}

// processNetworkPackets processes packets arriving from network and are destined to the application
func (d *DataPath) processNetworkPackets(p *packet.Packet) error {

	p.Print(packet.PacketStageIncoming)

	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessTCPNetPacket(p) {
			d.net.ServicePreDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("Pre service processing failed")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, err := d.processNetworkTCPPacket(p)
	if err != nil {
		d.net.AuthDropPackets++
		p.Print(packet.PacketFailureAuth)
		return fmt.Errorf("Processing failed %v", err)
	}

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPNetPacket(p, action) {
			d.net.ServicePostDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("Post service processing failed")
		}
	}

	// Accept the packet
	d.net.OutgoingPackets++
	p.Print(packet.PacketStageOutgoing)
	return nil
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *DataPath) processApplicationPackets(p *packet.Packet) error {

	if d.service != nil {
		// PreProcessServiceInterface
		if !d.service.PreProcessTCPAppPacket(p) {
			d.app.ServicePreDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("Pre service processing failed")
		}
	}

	p.Print(packet.PacketStageAuth)

	// Match the tags of the packet against the policy rules - drop if the lookup fails
	action, err := d.processApplicationTCPPacket(p)
	if err != nil {
		d.app.AuthDropPackets++
		p.Print(packet.PacketFailureAuth)
		return fmt.Errorf("Processing failed %v", err)
	}

	p.Print(packet.PacketStageService)

	if d.service != nil {
		// PostProcessServiceInterface
		if !d.service.PostProcessTCPAppPacket(p, action) {
			d.app.ServicePostDropPackets++
			p.Print(packet.PacketFailureService)
			return fmt.Errorf("Post service processing failed")
		}
	}

	// Accept the packet
	d.app.OutgoingPackets++
	p.Print(packet.PacketStageOutgoing)
	return nil
}

func (d *DataPath) createTCPAuthenticationOption(token []byte) []byte {

	tokenLen := uint8(len(token))
	options := []byte{packet.TCPAuthenticationOption, TCPAuthenticationOptionBaseLen + tokenLen, 0, 0}
	if tokenLen != 0 {
		options = append(options, token...)
	}
	return options
}

// createClaims creates the token with all the signature
func (d *DataPath) createPacketToken(ackToken bool, context *PUContext, connection *Connection) []byte {

	claims := &tokens.ConnectionClaims{
		LCL: connection.LocalContext,
		RMT: connection.RemoteContext,
	}

	if !ackToken {
		claims.T = context.Tags
	}

	return d.tokenEngine.CreateAndSign(ackToken, claims)

}

func (d *DataPath) parseAckToken(connection *Connection, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	claims, _ := d.tokenEngine.Decode(true, data, connection.RemotePublicKey)
	if claims == nil {
		return nil, fmt.Errorf("Cannot decode the token")
	}

	// Compare the incoming random context with the stored context
	matchLocal := bytes.Compare(claims.RMT, connection.LocalContext)
	matchRemote := bytes.Compare(claims.LCL, connection.RemoteContext)
	if matchLocal != 0 || matchRemote != 0 {
		return nil, fmt.Errorf("Failed to match context in ACK packet")
	}

	return claims, nil

}

func (d *DataPath) parsePacketToken(connection *Connection, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	claims, cert := d.tokenEngine.Decode(false, data, connection.RemotePublicKey)
	if claims == nil {
		return nil, fmt.Errorf("Cannot decode the token")
	}

	// We always a need a valid remote context ID
	remoteContextID, ok := claims.T[TransmitterLabel]
	if !ok {
		return nil, fmt.Errorf("No Transmitter Label ")
	}

	connection.RemotePublicKey = cert
	connection.RemoteContext = claims.LCL
	connection.RemoteContextID = remoteContextID

	return claims, nil

}

func (d *DataPath) processApplicationSynPacket(tcpPacket *packet.Packet) (interface{}, error) {

	var connection *Connection

	// Find the container context
	context, cerr := d.puTracker.Get(tcpPacket.SourceAddress.String())
	if cerr != nil {
		glog.V(7).Infoln("Container not found ", tcpPacket.SourceAddress.String())
		fmt.Println("Container not found ", tcpPacket.SourceAddress.String())
		return nil, nil
	}

	existing, err := d.appConnectionTracker.Get(tcpPacket.L4FlowHash())
	if err == nil {
		connection = existing.(*Connection)
	} else {
		connection = NewConnection()
	}

	// Create TCP Option
	tcpOptions := d.createTCPAuthenticationOption([]byte{})

	// Create a token
	tcpData := d.createPacketToken(false, context.(*PUContext), connection)

	// Track the connection
	connection.State = SynSend
	d.appConnectionTracker.AddOrUpdate(tcpPacket.L4FlowHash(), connection)
	d.contextConnectionTracker.AddOrUpdate(string(connection.LocalContext), connection)

	// Attach the tags to the packet. We use a trick to reduce the seq number from ISN so that when our component gets out of the way, the
	// sequence numbers between the TCP stacks automatically match
	tcpPacket.DecreaseTCPSeq(uint32(len(tcpData)-1) + (d.ackSize))
	tcpPacket.TCPDataAttach(tcpOptions, tcpData)

	tcpPacket.UpdateTCPChecksum()
	return nil, nil
}

func (d *DataPath) processApplicationSynAckPacket(tcpPacket *packet.Packet) (interface{}, error) {

	// Find the container context
	context, cerr := d.puTracker.Get(tcpPacket.SourceAddress.String())
	if cerr != nil {
		glog.V(7).Infoln("Container not found ", tcpPacket.SourceAddress.String())
		return nil, nil
	}

	// Create the reverse hash since we have cached based on the SYN and
	// Retrieve the connection context
	connection, err := d.networkConnectionTracker.Get(tcpPacket.L4ReverseFlowHash())
	if err != nil {
		glog.V(7).Infoln("Connection not found ", tcpPacket.SourceAddress.String())
		return nil, nil
	}

	// Process the packet if I am the right state. I should have either received a Syn packet or
	// I could have send a SynAck and this is a duplicate request since my response was lost.
	if connection.(*Connection).State == SynReceived || connection.(*Connection).State == SynAckSend {

		connection.(*Connection).State = SynAckSend

		// Create TCP Option
		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		// Create a token
		tcpData := d.createPacketToken(false, context.(*PUContext), connection.(*Connection))

		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(uint32(len(tcpData) - 1))
		tcpPacket.DecreaseTCPAck(d.ackSize)
		tcpPacket.TCPDataAttach(tcpOptions, tcpData)

		tcpPacket.UpdateTCPChecksum()
		return nil, nil
	}

	glog.V(1).Infoln("Received SynACK in wrong state ")
	return nil, fmt.Errorf("Received SynACK in wrong state ")
}

func (d *DataPath) processApplicationAckPacket(tcpPacket *packet.Packet) (interface{}, error) {

	// Find the container context
	context, cerr := d.puTracker.Get(tcpPacket.SourceAddress.String())
	if cerr != nil {
		glog.V(7).Infoln("Container not found ", tcpPacket.SourceAddress.String())
		return nil, nil
	}

	// Get the connection state. We need the state of the two random numbers
	connection, err := d.appConnectionTracker.Get(tcpPacket.L4FlowHash())
	if err != nil {
		glog.V(7).Infoln("Connection not found ", tcpPacket.SourceAddress.String())
		return nil, nil
	}

	// Only process in SynAckReceived state
	if connection.(*Connection).State == SynAckReceived {
		// Create a new token that includes the source and destinatio nonse
		// These are both challenges signed by the secret key and random for every
		// connection minimizing the chances of a replay attack
		token := d.createPacketToken(true, context.(*PUContext), connection.(*Connection))

		tcpOptions := d.createTCPAuthenticationOption([]byte{})

		if len(token) != int(d.ackSize) {
			glog.V(1).Infoln("Protocol Error", len(token))
			return nil, fmt.Errorf("Protocol Error %d", len(token))
		}

		// Attach the tags to the packet
		tcpPacket.DecreaseTCPSeq(d.ackSize)
		tcpPacket.TCPDataAttach(tcpOptions, token)

		tcpPacket.UpdateTCPChecksum()

		connection.(*Connection).State = AckSend

		return nil, nil
	}

	// Catch the first request packet
	if connection.(*Connection).State == AckSend {
		//Delete the state at this point .. There is a small chance that both packets are lost
		// and the other side will send us SYNACK again .. TBD if we need to change this
		d.contextConnectionTracker.Remove(string(connection.(*Connection).LocalContextID))
		d.appConnectionTracker.Remove(tcpPacket.L4FlowHash())
		return nil, nil
	}

	glog.V(1).Infoln("Received application ACK packet in the wrong state! ", connection.(*Connection).State)
	return nil, fmt.Errorf("Received application ACK packet in the wrong state! %v", connection.(*Connection).State)
}

//processApplicationTCPPacket will match incoming tags to a policy
func (d *DataPath) processApplicationTCPPacket(tcpPacket *packet.Packet) (interface{}, error) {

	// Initialize payload and options buffer with our new TCP options. Currenty using
	// the experimental option and padding the packet with two data fields to make
	// a 32-bit alignment. We have to use these data actually rather then send 0s.

	// State machine based on the flags
	switch tcpPacket.TCPFlags {
	case packet.TCPSynMask: //Processing SYN packet from Application
		action, err := d.processApplicationSynPacket(tcpPacket)
		return action, err

	case packet.TCPAckMask:
		action, err := d.processApplicationAckPacket(tcpPacket)
		return action, err

	case packet.TCPSynAckMask:
		action, err := d.processApplicationSynAckPacket(tcpPacket)
		return action, err
	}

	return nil, nil
}

func (d *DataPath) processNetworkSynPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {

	var connection *Connection
	// First check if a connection was previously established and this is a second SYNACK
	// packet. This means that our ACK packet was lost somewhere
	hash := tcpPacket.L4FlowHash()
	existing, err := d.networkConnectionTracker.Get(hash)

	if err == nil {
		connection = existing.(*Connection)
	} else {
		connection = NewConnection()
	}

	// Decode the JWT token using the context key
	// We need to add here to key renewal option where we decode with keys N, N-1
	// TBD
	claims, err := d.parsePacketToken(connection, tcpPacket.ReadTCPData())

	// If the token signature is not valid
	// We must drop the connection and we drop the Syn packet. The source will
	// retry but we have no state to maintain here.
	if err != nil || claims == nil {
		glog.V(1).Infoln("Syn packet dropped because of invalid token: ", err, claims)
		d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.InvalidToken, "", tcpPacket)
		return nil, fmt.Errorf("Syn packet dropped because of invalid token %v %+v", err, claims)
	}

	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
		glog.V(1).Infoln("TCP Authentication Option not found")
		d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.InvalidFormat, claims.T[TransmitterLabel], tcpPacket)
		return nil, fmt.Errorf("TCP Authentication Option not found %v", err)
	}

	// Remove any of our data from the packet. No matter what we don't need the
	// metadata any more.
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq((tcpDataLen - 1) + (d.ackSize))
	if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
		glog.V(1).Infoln("Syn packet dropped because of invalid format")
		d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.InvalidFormat, claims.T[TransmitterLabel], tcpPacket)
		return nil, fmt.Errorf("Syn packet dropped because of invalid format %v", err)
	}
	tcpPacket.DropDetachedBytes()

	tcpPacket.UpdateTCPChecksum()

	// Add the port as a label with an @ prefix. These labels are invalid otherwise
	// If all policies are restricted by port numbers this will allow port-specific policies
	claims.T[PortNumberLabelString] = strconv.Itoa(int(tcpPacket.DestinationPort))

	// Search the policy rules for a matching rule.
	if index, action := context.rules.Search(claims.T); index >= 0 {

		hash := tcpPacket.L4FlowHash()

		// Update the connection state and store the Nonse send to us by the host.
		// We use the nonse in the subsequent packets to achieve randomization.

		connection.State = SynReceived

		// Note that if the connection exists already we will just end-up replicating it. No
		// harm here.
		d.networkConnectionTracker.AddOrUpdate(hash, connection)

		// Accept the connection
		return action, nil
	}

	d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.PolicyDrop, claims.T[TransmitterLabel], tcpPacket)

	// Reject all other connections
	glog.V(1).Infoln("No matched tags - reject", claims.T)
	return nil, fmt.Errorf("No matched tags - reject %+v", claims.T)
}

func (d *DataPath) processNetworkSynAckPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {

	// First we need to receover our state of the connection. If we don't have any state
	// we drop the packets and the connections
	// connection, err := d.appConnectionTracker.Get(tcpPacket.L4ReverseFlowHash())

	tcpData := tcpPacket.ReadTCPData()
	if len(tcpData) == 0 {
		glog.V(1).Infoln("SynAck packet dropped because of missing token.")
		d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.MissingToken, "", tcpPacket)
		return nil, fmt.Errorf("SynAck packet dropped because of missing token.")
	}

	// Validate the certificate and parse the token
	claims, cert := d.tokenEngine.Decode(false, tcpData, nil)
	if claims == nil {
		glog.V(1).Infoln("Synack  packet dropped because of bad claims", claims)
		d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.MissingToken, "", tcpPacket)
		return nil, fmt.Errorf("Synack  packet dropped because of bad claims %v", claims)
	}

	// We always a need a valid remote context ID
	remoteContextID, ok := claims.T[TransmitterLabel]
	if !ok {
		return nil, fmt.Errorf("No remote context %v", claims.T)
	}

	connection, err := d.contextConnectionTracker.Get(string(claims.RMT))
	if err != nil {
		d.contextConnectionTracker.DumpStore()
		return nil, fmt.Errorf("No connection found for %v", claims.RMT)
	}

	connection.(*Connection).RemotePublicKey = cert
	connection.(*Connection).RemoteContext = claims.LCL
	connection.(*Connection).RemoteContextID = remoteContextID

	if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
		glog.V(1).Infoln("TCP Authentication Option not found")
		d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.InvalidFormat, claims.T[TransmitterLabel], tcpPacket)
		return nil, fmt.Errorf("TCP Authentication Option not found")
	}

	// Remove any of our data
	tcpDataLen := uint32(tcpPacket.IPTotalLength - tcpPacket.TCPDataStartBytes())
	tcpPacket.IncreaseTCPSeq(tcpDataLen - 1)
	tcpPacket.IncreaseTCPAck(d.ackSize)
	if err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen); err != nil {
		glog.V(1).Infoln("SynAck packet dropped because of invalid format")
		d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.InvalidFormat, claims.T[TransmitterLabel], tcpPacket)
		return nil, fmt.Errorf("SynAck packet dropped because of invalid format")
	}
	tcpPacket.DropDetachedBytes()

	tcpPacket.UpdateTCPChecksum()

	// We can now verify the reverse policy. The system requires that policy
	// is matched in both directions. We have to make this optional as it can
	// become a very strong condition

	if index, action := context.rules.Search(claims.T); !d.mutualAuthorization || index >= 0 {
		connection.(*Connection).State = SynAckReceived
		return action, nil
	}

	glog.V(1).Infoln("Dropping packet SYNACK at the network ")
	d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.PolicyDrop, claims.T[TransmitterLabel], tcpPacket)
	return nil, fmt.Errorf("Dropping packet SYNACK at the network ")
}

func (d *DataPath) processNetworkAckPacket(context *PUContext, tcpPacket *packet.Packet) (interface{}, error) {
	// Retrieve connection context
	hash := tcpPacket.L4FlowHash()
	connection, err := d.networkConnectionTracker.Get(hash)

	if err != nil {
		// IGNORE THIS PACKET
		// glog.V(2).Infoln("No context found for this packet")
		// d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.InvalidState, "", tcpPacket)
		return nil, nil
	}

	// Validate that the source/destination nonse matches. The signature has validated both directions
	if connection.(*Connection).State == SynAckSend {

		if err := tcpPacket.CheckTCPAuthenticationOption(TCPAuthenticationOptionBaseLen); err != nil {
			glog.V(1).Infoln("TCP Authentication Option not found")
			d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.InvalidFormat, "", tcpPacket)
			return nil, fmt.Errorf("TCP Authentication Option not found")
		}

		if _, err := d.parseAckToken(connection.(*Connection), tcpPacket.ReadTCPData()); err != nil {
			glog.V(1).Infoln("Ack packet dropped because singature validation failed", err)
			d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.InvalidFormat, "", tcpPacket)
			return nil, fmt.Errorf("Ack packet dropped because singature validation failed %v", err)
		}

		connection.(*Connection).State = AckProcessed
		// Remove any of our data
		tcpPacket.IncreaseTCPSeq(d.ackSize)
		err := tcpPacket.TCPDataDetach(TCPAuthenticationOptionBaseLen)
		if err != nil {
			glog.V(1).Infoln("Ack packet dropped because of invalid format")
			d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.InvalidFormat, "", tcpPacket)
			return nil, fmt.Errorf("Ack packet dropped because of invalid format %v", err)
		}

		tcpPacket.DropDetachedBytes()

		tcpPacket.UpdateTCPChecksum()

		// Delete the state
		glog.V(7).Infoln("processApplicationAckPacket() Connection Removed")
		d.networkConnectionTracker.Remove(hash)

		// We accept the packet as a new flow
		d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowAccept, "NA", connection.(*Connection).RemoteContextID, tcpPacket)

		// Accept the packet
		return nil, nil

	}

	// Catch the first request packets
	if connection.(*Connection).State == AckProcessed {
		// Safe to delete the state
		d.networkConnectionTracker.Remove(hash)
		return nil, nil
	}

	// Everything else is dropped
	d.logger.FlowEvent(context.ID, context.Tags, eventlog.FlowReject, eventlog.InvalidState, "", tcpPacket)
	return nil, fmt.Errorf("Ack packet dropped - no matching rules")
}

//processNetworkTCPPacket will match incoming tags to a policy
func (d *DataPath) processNetworkTCPPacket(tcpPacket *packet.Packet) (interface{}, error) {

	// Lookup the policy rules for the packet - Return false if they don't exist
	context, err := d.puTracker.Get(tcpPacket.DestinationAddress.String())
	if err != nil {
		glog.V(1).Infoln("Failed to retrieve context for this packet: ", tcpPacket)
		return nil, fmt.Errorf("Context not found for container %s %v", tcpPacket.DestinationAddress.String(), d.puTracker)
	}

	// Update connection state in the internal state machine tracker
	switch tcpPacket.TCPFlags {

	case packet.TCPSynMask:
		action, err := d.processNetworkSynPacket(context.(*PUContext), tcpPacket)
		return action, err

	case packet.TCPAckMask:
		action, err := d.processNetworkAckPacket(context.(*PUContext), tcpPacket)
		return action, err

	case packet.TCPSynAckMask:
		action, err := d.processNetworkSynAckPacket(context.(*PUContext), tcpPacket)
		return action, err

	default: // Ignore any other packet
		return nil, nil
	}
}
