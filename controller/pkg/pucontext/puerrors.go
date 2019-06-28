package pucontext

import (
	"sync/atomic"

	"go.aporeto.io/trireme-lib/collector"
)

// ErrorType custom counter error type
type ErrorType int

// PuError holds the string,integer for each error
type PuErrors struct {
	index ErrorType
	err   string
}

// Error Constants
const (
	ErrUnknownError ErrorType = iota
	ErrInvalidNetState
	ErrNonPUTraffic
	ErrNetSynNotSeen
	ErrNoConnFound
	ErrRejectPacket
	ErrTCPAuthNotFound
	ErrInvalidConnState
	ErrMarkNotFound
	ErrPortNotFound
	ErrContextIDNotFound
	ErrInvalidProtocol
	ErrServicePreprocessorFailed
	ErrServicePostprocessorFailed
	ErrDroppedExternalService
	ErrSynDroppedNoClaims
	ErrSynDroppedInvalidToken
	ErrSynDroppedTCPOption
	ErrSynDroppedInvalidFormat
	ErrSynRejectPacket
	ErrOutOfOrderSynAck
	ErrInvalidSynAck
	ErrSynAckMissingToken
	ErrSynAckBadClaims
	ErrSynAckMissingClaims
	ErrSynAckNoTCPAuthOption
	ErrSynAckInvalidFormat
	ErrSynAckClaimsMisMatch
	ErrSynAckRejected
	ErrSynAckDroppedExternalService
	ErrAckRejected
	ErrAckTCPNoTCPAuthOption
	ErrAckSigValidationFailed
	ErrAckInvalidFormat
	ErrAckInUnknownState
	ErrSynUnexpectedPacket
	ErrConnectionsProcessed
	ErrEncrConnectionsProcessed
	ErrUDPInvalidNetState
	ErrUDPDropSynAck
	ErrUDPDropFin
	ErrUDPDropPacket
	ErrUDPPreProcessingFailed
	ErrUDPRejected
	ErrUDPPostProcessingFailed
	ErrUDPNoConnection
	ErrUDPSynInvalidToken
	ErrUDPSynMissingClaims
	ErrUDPSynDroppedPolicy
	ErrUDPSynAckBadClaims
	ErrUDPSynAckMissingClaims
	ErrUDPSynAckPolicy
	ErrUdpAckInvalidSignature
	ErrUDPConnectionsProcessed
	ErrUDPContextIDNotFound
	ErrUDPDropQueueFull
	ErrUDPDropInNfQueue
	ErrUDPSynDropped
)

var counterNames = []string{
	ErrUnknownError:                 "UNKNOWNERROR",
	ErrInvalidNetState:              "INVALIDNETSTATE",
	ErrNonPUTraffic:                 "NONPUTRAFFIC",
	ErrNetSynNotSeen:                "SYNNOTSEEN",
	ErrNoConnFound:                  "CONNECTIONNOTFOUND",
	ErrRejectPacket:                 "REJECTEDPACKET",
	ErrTCPAuthNotFound:              "TCPAUTHENTICATIONOPTIONNOTFOUND",
	ErrInvalidConnState:             "INVALIDCONNECTIONSTATE",
	ErrMarkNotFound:                 "MARKNOTFOUND",
	ErrPortNotFound:                 "PORTNOTFOUND",
	ErrContextIDNotFound:            "CONTEXTNOTFOUND",
	ErrInvalidProtocol:              "INVALIDPROTOCOL",
	ErrServicePreprocessorFailed:    "PREPROCESSINGFAILED",
	ErrServicePostprocessorFailed:   "POSTPROCESSINGFAILED",
	ErrDroppedExternalService:       "ACLSYNDROPPED",
	ErrSynDroppedNoClaims:           "SYNDROPPEDNOCLAIMS",
	ErrSynDroppedInvalidToken:       "SYNDROPPEDINVALIDTOKEN",
	ErrSynDroppedTCPOption:          "SYNDROPPEDAUTHOPTIONNOTFOUND",
	ErrSynDroppedInvalidFormat:      "SYNDROPPEDINVALIDFORMAT",
	ErrSynRejectPacket:              "SYNDROPPEDPOLICY",
	ErrOutOfOrderSynAck:             "UNEXPECTEDSYNACK",
	ErrInvalidSynAck:                "DEADPUSYNACK",
	ErrSynAckMissingToken:           "SYNACKDROPPEDINVALIDTOKEN",
	ErrSynAckBadClaims:              "SYNACKDROPPEDBADCLAIMS",
	ErrSynAckMissingClaims:          "SYNACKDROPPEDNOCLAIMS",
	ErrSynAckNoTCPAuthOption:        "SYNACKAUTHOPTIONNOTFOUND",
	ErrSynAckInvalidFormat:          "SYNACKDROPPEDINVALIDFORMAT",
	ErrSynAckClaimsMisMatch:         "SYNACKDROPPEDCLAIMSMISMATCH",
	ErrSynAckRejected:               "SYNACKDROPPEDPOLICY",
	ErrSynAckDroppedExternalService: "ERRSYNACKDROPPEDEXTERNALSERVICE",
	ErrAckRejected:                  "ACKDROPPEDPOLICY",
	ErrAckTCPNoTCPAuthOption:        "ACKDROPPEDAUTHOPTIONNOTFOUND",
	ErrAckSigValidationFailed:       "ACKDROPPEDSIGVALIDATIONFAILED",
	ErrAckInvalidFormat:             "ACKDROPPEDINVALIDFORMAT",
	ErrAckInUnknownState:            "ACKDROPPEDUNKNOWNCONNSTATE",
	ErrSynUnexpectedPacket:          "SYNUNEXPECTEDPACKET",
	ErrConnectionsProcessed:         "CONNECTIONSPROCESSED",
	ErrEncrConnectionsProcessed:     "ENCRCONNECTIONSPROCESSED",
	ErrUDPInvalidNetState:           "UDPINVALIDNETSTATE",
	ErrUDPDropSynAck:                "UDPDROPSYNACK",
	ErrUDPDropFin:                   "UDPDROPFIN",
	ErrUDPDropPacket:                "UDPDROPPACKET",
	ErrUDPPreProcessingFailed:       "UDPPREPROCESSINGFAILED",
	ErrUDPRejected:                  "UDPREJECTED",
	ErrUDPPostProcessingFailed:      "UDPPOSTPROCESSINGFAILED",
	ErrUDPNoConnection:              "UDPDROPNOCONNECTION",
	ErrUDPSynInvalidToken:           "UDPSYNINVALIDTOKEN",
	ErrUDPSynMissingClaims:          "UDPSYNMISSINGCLAIMS",
	ErrUDPSynDroppedPolicy:          "UDPSYNDROPPEDPOLICY",
	ErrUDPSynAckBadClaims:           "UDPSYNACKBADCLAIMS",
	ErrUDPSynAckMissingClaims:       "UDPSYNACKMISSINGCLAIMS",
	ErrUDPSynAckPolicy:              "UDPSYNACKPOLICY",
	ErrUdpAckInvalidSignature:       "UDPACKINVALIDSIGNATURE",
	ErrUDPConnectionsProcessed:      "UDPCONNECTIONSPROCESSED",
	ErrUDPContextIDNotFound:         "UDPCONTEXTIDNOTFOUND",
	ErrUDPDropQueueFull:             "UDPDROPQUEUEFULL",
	ErrUDPDropInNfQueue:             "UDPDROPINNFQUEUE",
	ErrUDPSynDropped:                "UDPSYNDROPPED",
}

var countedEvents = []PuErrors{
	// sentinel value insert new ones below this
	ErrUnknownError: PuErrors{
		index: ErrUnknownError,
		err:   "Unknown Error",
	},
	ErrInvalidNetState: PuErrors{
		index: ErrInvalidNetState,

		err: "Invalid net state",
	},
	ErrNonPUTraffic: PuErrors{
		index: ErrNonPUTraffic,

		err: "Traffic belongs to a PU we are not monitoring",
	},
	ErrNetSynNotSeen: PuErrors{
		index: ErrNetSynNotSeen,
		err:   "Network Syn packet was not seen",
	},
	ErrNoConnFound: PuErrors{
		index: ErrNoConnFound,
		err:   "no context or connection found",
	},
	ErrRejectPacket: PuErrors{
		index: ErrRejectPacket,
		err:   "Reject the packet as per policy",
	},
	ErrTCPAuthNotFound: PuErrors{
		index: ErrTCPAuthNotFound,
		err:   "TCP authentication option not found",
	},
	ErrInvalidConnState: PuErrors{
		index: ErrInvalidConnState,
		err:   "Invalid connection state",
	},
	ErrMarkNotFound: PuErrors{
		index: ErrMarkNotFound,
		err:   "PU mark not found",
	},
	ErrPortNotFound: PuErrors{
		index: ErrPortNotFound,
		err:   "Port not found",
	},
	ErrContextIDNotFound: PuErrors{
		index: ErrContextIDNotFound,
		err:   "unable to find contextID",
	},
	ErrInvalidProtocol: PuErrors{
		index: ErrInvalidProtocol,
		err:   "Invalid Protocol",
	},
	ErrServicePreprocessorFailed: PuErrors{
		index: ErrServicePreprocessorFailed,
		err:   "pre service processing failed for network packet",
	},
	ErrServicePostprocessorFailed: PuErrors{
		index: ErrServicePostprocessorFailed,
		err:   "post service processing failed for network packet",
	},
	ErrDroppedExternalService: PuErrors{
		index: ErrDroppedExternalService,
		err:   "No acls found for external services. Dropping application syn packet",
	},
	ErrSynDroppedNoClaims: PuErrors{
		index: ErrSynDroppedNoClaims,
		err:   "Syn packet dropped because of no claims",
	},
	ErrSynDroppedInvalidToken: PuErrors{
		index: ErrSynDroppedInvalidToken,
		err:   "Syn packet dropped because of invalid token",
	},
	ErrSynDroppedTCPOption: PuErrors{
		index: ErrSynDroppedTCPOption,
		err:   "TCP authentication option not found",
	},
	ErrSynDroppedInvalidFormat: PuErrors{
		index: ErrSynDroppedInvalidFormat,
		err:   "Syn packet dropped because of invalid format",
	},
	ErrSynRejectPacket: PuErrors{
		index: ErrSynRejectPacket,
		err:   "Syn Dropped due to policy",
	},
	ErrOutOfOrderSynAck: PuErrors{
		index: ErrOutOfOrderSynAck,
		err:   "synack for flow with processed finack",
	},
	ErrInvalidSynAck: PuErrors{
		index: ErrInvalidSynAck,
		err:   "PU is already dead - drop SynAck packet",
	},
	ErrSynAckMissingToken: PuErrors{
		index: ErrSynAckMissingToken,
		err:   "SynAck packet dropped because of missing token",
	},
	ErrSynAckBadClaims: PuErrors{
		index: ErrSynAckBadClaims,
		err:   "SynAck packet dropped because of bad claims",
	},
	ErrSynAckMissingClaims: PuErrors{
		index: ErrSynAckMissingClaims,
		err:   "SynAck packet dropped because of no claims",
	},
	ErrSynAckNoTCPAuthOption: PuErrors{
		index: ErrSynAckNoTCPAuthOption,
		err:   "TCP authentication option not found",
	},
	ErrSynAckInvalidFormat: PuErrors{
		index: ErrSynAckInvalidFormat,
		err:   "SynAck packet dropped because of invalid format",
	},
	ErrSynAckClaimsMisMatch: PuErrors{
		index: ErrSynAckClaimsMisMatch,
		err:   "syn/ack packet dropped because of encryption mismatch",
	},
	ErrSynAckRejected: PuErrors{
		index: ErrSynAckRejected,
		err:   "dropping because of reject rule on transmitter",
	},
	ErrSynAckDroppedExternalService: PuErrors{
		index: ErrSynAckDroppedExternalService,
		err:   "SynAck from external service dropped",
	},
	ErrAckRejected: PuErrors{
		index: ErrAckRejected,
		err:   "Reject Ack packet as per policy",
	},
	ErrAckTCPNoTCPAuthOption: PuErrors{
		index: ErrAckTCPNoTCPAuthOption,
		err:   "TCP authentication option not found",
	},
	ErrAckSigValidationFailed: PuErrors{
		index: ErrAckSigValidationFailed,
		err:   "Ack packet dropped because signature validation failed",
	},
	ErrAckInvalidFormat: PuErrors{
		index: ErrAckInvalidFormat,
		err:   "Ack packet dropped because of invalid format",
	},
	ErrAckInUnknownState: PuErrors{
		index: ErrAckInUnknownState,
		err:   "sending finack Ack Received in uknown connection state",
	},
	ErrSynUnexpectedPacket: PuErrors{
		index: ErrSynUnexpectedPacket,
		err:   "Received syn packet from unknown PU",
	},
	ErrConnectionsProcessed: PuErrors{
		index: ErrConnectionsProcessed,
		err:   "",
	},
	ErrUDPInvalidNetState: PuErrors{
		index: ErrUDPInvalidNetState,
		err:   "Packet received in invalid udp network state",
	},
	ErrUDPDropSynAck: PuErrors{
		index: ErrUDPDropSynAck,
		err:   "No connection.Drop the syn ack packet",
	},
	ErrUDPDropFin: PuErrors{
		index: ErrUDPDropFin,
		err:   "Dropped FIN packet",
	},
	ErrUDPDropPacket: PuErrors{
		index: ErrUDPDropPacket,
		err:   "Dropped network udp data packet",
	},
	ErrUDPPreProcessingFailed: PuErrors{
		index: ErrUDPPreProcessingFailed,
		err:   "Pre processing failed",
	},
	ErrUDPRejected: PuErrors{
		index: ErrUDPRejected,
		err:   "UDP packet rejected due to policy",
	},
	ErrUDPPostProcessingFailed: PuErrors{
		index: ErrUDPPostProcessingFailed,
		err:   "UDP packet failed postprocessing",
	},
	ErrUDPSynInvalidToken: PuErrors{
		index: ErrUDPSynInvalidToken,
		err:   "UDP syn packet dropped invalid token",
	},
	ErrUDPSynMissingClaims: PuErrors{
		index: ErrUDPSynMissingClaims,
		err:   "UDP syn packet dropped missing claims",
	},

	ErrUDPSynDroppedPolicy: PuErrors{
		index: ErrUDPSynDroppedPolicy,
		err:   "UDP syn packet dropped policy",
	},
	ErrUDPSynAckBadClaims: PuErrors{
		index: ErrUDPSynAckBadClaims,
		err:   "UDP synack packet dropped bad claims",
	},
	ErrUDPSynAckMissingClaims: PuErrors{
		index: ErrUDPSynAckMissingClaims,
		err:   "UDP synack packet dropped missing claims",
	},
	ErrUDPSynAckPolicy: PuErrors{
		index: ErrUDPSynAckPolicy,
		err:   "UDP syn ack packet dropped policy",
	},
	ErrUdpAckInvalidSignature: PuErrors{
		index: ErrUdpAckInvalidSignature,
		err:   "UDP ack packet dropped invalid signature",
	},
	ErrUDPConnectionsProcessed: PuErrors{
		index: ErrUDPConnectionsProcessed,
		err:   "UDP connections processed",
	},
	ErrUDPContextIDNotFound: PuErrors{
		index: ErrUDPContextIDNotFound,
		err:   "UDP packet ContextID not found ",
	},
	ErrUDPDropQueueFull: PuErrors{
		index: ErrUDPDropQueueFull,
		err:   "UDP packet dropped queue full",
	},
	ErrUDPDropInNfQueue: PuErrors{
		index: ErrUDPDropInNfQueue,
		err:   "UDP packet dropped in NfQueue",
	},
	ErrUDPSynDropped: PuErrors{
		index: ErrUDPSynDropped,
		err:   "UDP syn packet dropped missing claims",
	},
}

// PuContextError increments the error counter and returns an error
func (p *PUContext) PuContextError(err ErrorType, logMsg string) error {
	atomic.AddUint32(&p.counters[int(err)], 1)
	return countedEvents[err]
}

// PuContextError increments a global unknown PU counter and returns an error
func PuContextError(err ErrorType, logMsg string) error {
	atomic.AddUint32(&unknownPU.counters[int(err)], 1)
	return countedEvents[err]
}

// GetErrorCounters returns the error counters and resets the counters to zero
func (p *PUContext) GetErrorCounters() []collector.Counters {
	report := make([]collector.Counters, len(countedEvents))
	p.Lock()
	defer p.Unlock()
	for index, val := range p.counters {
		report[index] = collector.Counters{
			Name:  counterNames[index],
			Value: atomic.SwapUint32(&val, 0),
		}

	}
	return report
}

// GetErrorCounters returns the counters for packets whose PU is not known
func GetErrorCounters() []collector.Counters {
	report := make([]collector.Counters, len(countedEvents))
	unknownPU.Lock()
	defer unknownPU.Unlock()
	for index, val := range unknownPU.counters {
		report[index] = collector.Counters{
			Name:  counterNames[index],
			Value: atomic.SwapUint32(&val, 0),
		}

	}
	return report
}

// GetErrorr gives the errortype for an error
func GetError(err error) ErrorType {
	errType, ok := err.(PuErrors)
	if !ok {
		return ErrUnknownError
	}
	return errType.index
}

// ToError returns converts error from ErrorType
func ToError(errType ErrorType) error {
	return countedEvents[errType]
}

// Error implemented to satisfy the error interface
func (e PuErrors) Error() string {
	return e.err
}
