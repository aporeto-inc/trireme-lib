package pucontext

import "errors"

type PuErrors struct {
	err error
}
type ErrorType int

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
	ErrAckRejected
	ErrAckTCPNoTCPAuthOption
	ErrAckSigValidationFailed
	ErrAckInvalidFormat
)

var puerrors = []PuErrors{
	ErrInvalidNetState: PuErrors{
		err: errors.New("Invalid net state"),
	},
	ErrNonPUTraffic: PuErrors{
		err: errors.New("Traffic belongs to a PU we are not monitoring"),
	},
	ErrNetSynNotSeen: PuErrors{
		err: errors.New("Network Syn packet was not seen"),
	},
	ErrNoConnFound: PuErrors{
		err: errors.New("no context or connection found"),
	},
	ErrRejectPacket: PuErrors{
		err: errors.New("Reject the packet as per policy"),
	},
	ErrTCPAuthNotFound: PuErrors{
		err: errors.New("TCP authentication option not found"),
	},
	ErrInvalidConnState: PuErrors{
		err: errors.New("Invalid connection state"),
	},
	ErrMarkNotFound: PuErrors{
		err: errors.New("PU mark not found"),
	},
	ErrPortNotFound: PuErrors{
		err: errors.New("Port not found"),
	},
	ErrContextIDNotFound: PuErrors{
		err: errors.New("unable to find contextID"),
	},
	ErrInvalidProtocol: PuErrors{
		err: errors.New("Invalid Protocol"),
	},
	ErrServicePreprocessorFailed: PuErrors{
		err: errors.New("pre service processing failed for network packet"),
	},
	ErrServicePostprocessorFailed: PuErrors{
		err: errors.New("post service processing failed for network packet"),
	},
	ErrDroppedExternalService: PuErrors{
		err: errors.New("No acls found for external services. Dropping application syn packet"),
	},
	ErrSynDroppedNoClaims: PuErrors{
		err: errors.New("Syn packet dropped because of no claims"),
	},
	ErrSynDroppedInvalidToken: PuErrors{
		err: errors.New("Syn packet dropped because of invalid token"),
	},
	ErrSynDroppedTCPOption: PuErrors{
		err: errors.New("TCP authentication option not found"),
	},
	ErrSynDroppedInvalidFormat: PuErrors{
		err: errors.New("Syn packet dropped because of invalid format"),
	},
	ErrOutOfOrderSynAck: PuErrors{
		err: errors.New("synack for flow with processed finack"),
	},
	ErrInvalidSynAck: PuErrors{
		err: errors.New("PU is already dead - drop SynAck packet"),
	},
	ErrSynAckMissingToken: PuErrors{
		err: errors.New("SynAck packet dropped because of missing token"),
	},
	ErrSynAckBadClaims: PuErrors{
		err: errors.New("SynAck packet dropped because of bad claims"),
	},
	ErrSynAckMissingClaims: PuErrors{
		err: errors.New("SynAck packet dropped because of no claims"),
	},
	ErrSynAckNoTCPAuthOption: PuErrors{
		err: errors.New("TCP authentication option not found"),
	},
	ErrSynAckInvalidFormat: PuErrors{
		err: errors.New("SynAck packet dropped because of invalid format"),
	},
	ErrSynAckClaimsMisMatch: PuErrors{
		err: errors.New("syn/ack packet dropped because of encryption mismatch"),
	},
	ErrSynAckRejected: PuErrors{
		err: errors.New("dropping because of reject rule on transmitter"),
	},
	ErrAckRejected: PuErrors{
		err: errors.New("Reject Ack packet as per policy"),
	},
	ErrAckTCPNoTCPAuthOption: PuErrors{
		err: errors.New("TCP authentication option not found"),
	},
	ErrAckSigValidationFailed: PuErrors{
		err: errors.New("Ack packet dropped because signature validation failed"),
	},
	ErrAckInvalidFormat: PuErrors{
		err: errors.New("Ack packet dropped because of invalid format"),
	},
}

func (p *PUContext) PuContextError(err ErrorType, logMsg string) error {
	return puerrors[err].err
}

func PuContextError(err ErrorType, logMsg string) error {
	return puerrors[err].err
}
