package pucontext

type ErrorType int
type PuErrors struct {
	index ErrorType
	err   string
}

const (
	ErrInvalidNetState ErrorType = iota
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
	ErrUnknownError
)

var puerrors = []PuErrors{
	ErrInvalidNetState: PuErrors{
		index: ErrInvalidNetState,
		err:   "Invalid net state",
	},
	ErrNonPUTraffic: PuErrors{
		index: ErrNonPUTraffic,
		err:   "Traffic belongs to a PU we are not monitoring",
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
	ErrUnknownError: PuErrors{
		index: ErrUnknownError,
		err:   "Unknown Error",
	},
}

func (p *PUContext) PuContextError(err ErrorType, logMsg string) error {
	return puerrors[err]
}

func PuContextError(err ErrorType, logMsg string) error {
	return puerrors[err]
}

func GetError(err error) ErrorType {
	errType, ok := err.(PuErrors)
	if !ok {
		return ErrUnknownError
	}
	return errType.index
}

func ToError(errType ErrorType) error {
	return puerrors[errType]
}
func (e PuErrors) Error() string {
	return e.err
}
