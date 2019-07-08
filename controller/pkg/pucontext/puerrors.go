package pucontext

import (
	"sync/atomic"

	"go.aporeto.io/trireme-lib/collector"
	"go.uber.org/zap"
)

// ErrorType custom counter error type
type ErrorType int

// PuErrors holds the string,integer for each error
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
	ErrUDPInvalidSignature
	ErrUDPConnectionsProcessed
	ErrUDPContextIDNotFound
	ErrUDPDropQueueFull
	ErrUDPDropInNfQueue
	ErrUDPSynDropped
)

// CounterNames is the name for each error reported to the collector
var CounterNames = []string{
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
	ErrUDPInvalidSignature:          "UDPACKINVALIDSIGNATURE",
	ErrUDPConnectionsProcessed:      "UDPCONNECTIONSPROCESSED",
	ErrUDPContextIDNotFound:         "UDPCONTEXTIDNOTFOUND",
	ErrUDPDropQueueFull:             "UDPDROPQUEUEFULL",
	ErrUDPDropInNfQueue:             "UDPDROPINNFQUEUE",
	ErrUDPSynDropped:                "UDPSYNDROPPED",
}

var countedEvents = []PuErrors{
	// sentinel value insert new ones below this
	ErrUnknownError: {
		index: ErrUnknownError,
		err:   "Unknown Error",
	},
	ErrInvalidNetState: {
		index: ErrInvalidNetState,

		err: "Invalid net state",
	},
	ErrNonPUTraffic: {
		index: ErrNonPUTraffic,

		err: "Traffic belongs to a PU we are not monitoring",
	},
	ErrNetSynNotSeen: {
		index: ErrNetSynNotSeen,
		err:   "Network Syn packet was not seen",
	},
	ErrNoConnFound: {
		index: ErrNoConnFound,
		err:   "no context or connection found",
	},
	ErrRejectPacket: {
		index: ErrRejectPacket,
		err:   "Reject the packet as per policy",
	},
	ErrTCPAuthNotFound: {
		index: ErrTCPAuthNotFound,
		err:   "TCP authentication option not found",
	},
	ErrInvalidConnState: {
		index: ErrInvalidConnState,
		err:   "Invalid connection state",
	},
	ErrMarkNotFound: {
		index: ErrMarkNotFound,
		err:   "PU mark not found",
	},
	ErrPortNotFound: {
		index: ErrPortNotFound,
		err:   "Port not found",
	},
	ErrContextIDNotFound: {
		index: ErrContextIDNotFound,
		err:   "unable to find contextID",
	},
	ErrInvalidProtocol: {
		index: ErrInvalidProtocol,
		err:   "Invalid Protocol",
	},
	ErrServicePreprocessorFailed: {
		index: ErrServicePreprocessorFailed,
		err:   "pre service processing failed for network packet",
	},
	ErrServicePostprocessorFailed: {
		index: ErrServicePostprocessorFailed,
		err:   "post service processing failed for network packet",
	},
	ErrDroppedExternalService: {
		index: ErrDroppedExternalService,
		err:   "No acls found for external services. Dropping application syn packet",
	},
	ErrSynDroppedNoClaims: {
		index: ErrSynDroppedNoClaims,
		err:   "Syn packet dropped because of no claims",
	},
	ErrSynDroppedInvalidToken: {
		index: ErrSynDroppedInvalidToken,
		err:   "Syn packet dropped because of invalid token",
	},
	ErrSynDroppedTCPOption: {
		index: ErrSynDroppedTCPOption,
		err:   "TCP authentication option not found",
	},
	ErrSynDroppedInvalidFormat: {
		index: ErrSynDroppedInvalidFormat,
		err:   "Syn packet dropped because of invalid format",
	},
	ErrSynRejectPacket: {
		index: ErrSynRejectPacket,
		err:   "Syn Dropped due to policy",
	},
	ErrOutOfOrderSynAck: {
		index: ErrOutOfOrderSynAck,
		err:   "synack for flow with processed finack",
	},
	ErrInvalidSynAck: {
		index: ErrInvalidSynAck,
		err:   "PU is already dead - drop SynAck packet",
	},
	ErrSynAckMissingToken: {
		index: ErrSynAckMissingToken,
		err:   "SynAck packet dropped because of missing token",
	},
	ErrSynAckBadClaims: {
		index: ErrSynAckBadClaims,
		err:   "SynAck packet dropped because of bad claims",
	},
	ErrSynAckMissingClaims: {
		index: ErrSynAckMissingClaims,
		err:   "SynAck packet dropped because of no claims",
	},
	ErrSynAckNoTCPAuthOption: {
		index: ErrSynAckNoTCPAuthOption,
		err:   "TCP authentication option not found",
	},
	ErrSynAckInvalidFormat: {
		index: ErrSynAckInvalidFormat,
		err:   "SynAck packet dropped because of invalid format",
	},
	ErrSynAckClaimsMisMatch: {
		index: ErrSynAckClaimsMisMatch,
		err:   "syn/ack packet dropped because of encryption mismatch",
	},
	ErrSynAckRejected: {
		index: ErrSynAckRejected,
		err:   "dropping because of reject rule on transmitter",
	},
	ErrSynAckDroppedExternalService: {
		index: ErrSynAckDroppedExternalService,
		err:   "SynAck from external service dropped",
	},
	ErrAckRejected: {
		index: ErrAckRejected,
		err:   "Reject Ack packet as per policy",
	},
	ErrAckTCPNoTCPAuthOption: {
		index: ErrAckTCPNoTCPAuthOption,
		err:   "TCP authentication option not found",
	},
	ErrAckSigValidationFailed: {
		index: ErrAckSigValidationFailed,
		err:   "Ack packet dropped because signature validation failed",
	},
	ErrAckInvalidFormat: {
		index: ErrAckInvalidFormat,
		err:   "Ack packet dropped because of invalid format",
	},
	ErrAckInUnknownState: {
		index: ErrAckInUnknownState,
		err:   "sending finack Ack Received in uknown connection state",
	},
	ErrSynUnexpectedPacket: {
		index: ErrSynUnexpectedPacket,
		err:   "Received syn packet from unknown PU",
	},
	ErrConnectionsProcessed: {
		index: ErrConnectionsProcessed,
		err:   "",
	},
	ErrEncrConnectionsProcessed: {
		index: ErrEncrConnectionsProcessed,
		err:   "encrypted connections processed",
	},
	ErrUDPInvalidNetState: {
		index: ErrUDPInvalidNetState,
		err:   "Packet received in invalid udp network state",
	},
	ErrUDPDropSynAck: {
		index: ErrUDPDropSynAck,
		err:   "No connection.Drop the syn ack packet",
	},
	ErrUDPDropFin: {
		index: ErrUDPDropFin,
		err:   "Dropped FIN packet",
	},
	ErrUDPDropPacket: {
		index: ErrUDPDropPacket,
		err:   "Dropped network udp data packet",
	},
	ErrUDPPreProcessingFailed: {
		index: ErrUDPPreProcessingFailed,
		err:   "Pre processing failed",
	},
	ErrUDPRejected: {
		index: ErrUDPRejected,
		err:   "UDP packet rejected due to policy",
	},
	ErrUDPPostProcessingFailed: {
		index: ErrUDPPostProcessingFailed,
		err:   "UDP packet failed postprocessing",
	},
	ErrUDPNoConnection: {
		index: ErrUDPNoConnection,
		err:   "UDP packet dropped no connection",
	},
	ErrUDPSynInvalidToken: {
		index: ErrUDPSynInvalidToken,
		err:   "UDP syn packet dropped invalid token",
	},
	ErrUDPSynMissingClaims: {
		index: ErrUDPSynMissingClaims,
		err:   "UDP syn packet dropped missing claims",
	},

	ErrUDPSynDroppedPolicy: {
		index: ErrUDPSynDroppedPolicy,
		err:   "UDP syn packet dropped policy",
	},
	ErrUDPSynAckBadClaims: {
		index: ErrUDPSynAckBadClaims,
		err:   "UDP synack packet dropped bad claims",
	},
	ErrUDPSynAckMissingClaims: {
		index: ErrUDPSynAckMissingClaims,
		err:   "UDP synack packet dropped missing claims",
	},
	ErrUDPSynAckPolicy: {
		index: ErrUDPSynAckPolicy,
		err:   "UDP syn ack packet dropped policy",
	},
	ErrUDPInvalidSignature: {
		index: ErrUDPInvalidSignature,
		err:   "UDP ack packet dropped invalid signature",
	},
	ErrUDPConnectionsProcessed: {
		index: ErrUDPConnectionsProcessed,
		err:   "UDP connections processed",
	},
	ErrUDPContextIDNotFound: {
		index: ErrUDPContextIDNotFound,
		err:   "UDP packet ContextID not found ",
	},
	ErrUDPDropQueueFull: {
		index: ErrUDPDropQueueFull,
		err:   "UDP packet dropped queue full",
	},
	ErrUDPDropInNfQueue: {
		index: ErrUDPDropInNfQueue,
		err:   "UDP packet dropped in NfQueue",
	},
	ErrUDPSynDropped: {
		index: ErrUDPSynDropped,
		err:   "UDP syn packet dropped missing claims",
	},
}

// PuContextError increments the error counter and returns an error
func (p *PUContext) PuContextError(err ErrorType, logMsg string) error { // nolint
	atomic.AddUint32(&p.counters[int(err)], 1)
	zap.L().Debug(" ", zap.String("log", logMsg),
		zap.String("contextID", p.ID()))
	return countedEvents[err]
}

// PuContextError increments a global unknown PU counter and returns an error
func PuContextError(err ErrorType, logMsg string) error { // nolint
	atomic.AddUint32(&unknownPU.counters[int(err)], 1)

	return countedEvents[err]
}

// GetErrorCounters returns the error counters and resets the counters to zero
func (p *PUContext) GetErrorCounters() []collector.Counters {
	report := make([]collector.Counters, len(countedEvents))
	p.Lock()
	defer p.Unlock()
	for index := range p.counters {
		report[index] = collector.Counters{
			Name:  CounterNames[index],
			Value: atomic.SwapUint32(&p.counters[index], 0),
		}

	}

	return report
}

// GetErrorCounters returns the counters for packets whose PU is not known
func GetErrorCounters() []collector.Counters {
	report := make([]collector.Counters, len(countedEvents))
	unknownPU.Lock()
	defer unknownPU.Unlock()
	for index := range unknownPU.counters {
		report[index] = collector.Counters{
			Name:  CounterNames[index],
			Value: atomic.SwapUint32(&unknownPU.counters[index], 0),
		}

	}

	return report
}

// GetError gives the errortype for an error
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
