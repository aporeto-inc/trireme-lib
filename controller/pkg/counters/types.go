package counters

import "sync"

type Counters struct {
	counters []uint32

	sync.RWMutex
}

const (
	totalCounters = 100
)

// CounterTypes custom counter error type
type CounterTypes int

// WARNING: Append any new counters at the end of the list.
// DO NOT CHANGE EXISTING ORDER.
const (
	ErrUnknownError = iota
	ErrNonPUTraffic
	ErrNoConnFound
	ErrRejectPacket

	ErrMarkNotFound
	ErrPortNotFound
	ErrContextIDNotFound
	ErrInvalidProtocol

	ErrConnectionsProcessed
	ErrEncrConnectionsProcessed

	ErrUDPDropFin
	ErrUDPSynDroppedInvalidToken
	ErrUDPSynAckInvalidToken
	ErrUDPAckInvalidToken

	ErrUDPConnectionsProcessed
	ErrUDPContextIDNotFound
	ErrUDPDropQueueFull
	ErrUDPDropInNfQueue

	// 2
	// Processors
	ErrAppServicePreProcessorFailed
	ErrAppServicePostProcessorFailed
	ErrNetServicePreProcessorFailed
	ErrNetServicePostProcessorFailed

	// Syn
	ErrSynTokenFailed
	ErrSynDroppedInvalidToken
	ErrSynDroppedTCPOption
	ErrSynDroppedInvalidFormat
	ErrSynRejectPacket
	ErrSynDroppedExternalService
	ErrSynUnexpectedPacket
	ErrInvalidNetSynState
	ErrNetSynNotSeen

	// Synack
	ErrSynAckTokenFailed
	ErrOutOfOrderSynAck
	ErrInvalidSynAck
	ErrSynAckInvalidToken
	ErrSynAckMissingToken
	ErrSynAckNoTCPAuthOption
	ErrSynAckInvalidFormat
	ErrSynAckClaimsMisMatch
	ErrSynAckRejected
	ErrSynAckDroppedExternalService
	ErrInvalidNetSynAckState

	// Ack
	ErrAckTokenFailed
	ErrAckRejected
	ErrAckTCPNoTCPAuthOption
	ErrAckInvalidFormat
	ErrAckInvalidToken
	ErrAckInUnknownState
	ErrInvalidNetAckState

	// UDP Processors
	ErrUDPAppPreProcessingFailed
	ErrUDPAppPostProcessingFailed
	ErrUDPNetPreProcessingFailed
	ErrUDPNetPostProcessingFailed

	// UDP Syn
	ErrUDPSynInvalidToken
	ErrUDPSynMissingClaims
	ErrUDPSynDroppedPolicy

	// UDP SynAck
	ErrUDPSynAckNoConnection
	ErrUDPSynAckPolicy

	// Dropped packets
	ErrDroppedTCPPackets
	ErrDroppedUDPPackets
	ErrDroppedICMPPackets
	ErrDroppedDNSPackets
	ErrDroppedDHCPPackets
	ErrDroppedNTPPackets

	// Connections expired
	ErrTCPConnectionsExpired
	ErrUDPConnectionsExpired

	//3

	ErrSynTokenTooSmall
	ErrSynTokenEncodeFailed
	ErrSynTokenHashFailed
	ErrSynTokenSignFailed
	ErrSynSharedSecretMissing
	ErrSynInvalidSecret
	ErrSynInvalidTokenLength
	ErrSynMissingSignature
	ErrSynInvalidSignature
	ErrSynCompressedTagMismatch
	ErrSynDatapathVersionMismatch
	ErrSynTokenDecodeFailed
	ErrSynTokenExpired
	ErrSynSignatureMismatch
	ErrSynSharedKeyHashFailed
	ErrSynPublicKeyFailed

	ErrSynAckTokenTooSmall
	ErrSynAckTokenEncodeFailed
	ErrSynAckTokenHashFailed
	ErrSynAckTokenSignFailed
	ErrSynAckSharedSecretMissing
	ErrSynAckInvalidSecret
	ErrSynAckInvalidTokenLength
	ErrSynAckMissingSignature
	ErrSynAckInvalidSignature
	ErrSynAckCompressedTagMismatch
	ErrSynAckDatapathVersionMismatch
	ErrSynAckTokenDecodeFailed
	ErrSynAckTokenExpired
	ErrSynAckSignatureMismatch
	ErrSynAckSharedKeyHashFailed
	ErrSynAckPublicKeyFailed

	ErrAckTokenTooSmall
	ErrAckTokenEncodeFailed
	ErrAckTokenHashFailed
	ErrAckTokenSignFailed
	ErrAckSharedSecretMissing
	ErrAckInvalidSecret
	ErrAckInvalidTokenLength
	ErrAckMissingSignature
	ErrAckInvalidSignature
	ErrAckCompressedTagMismatch
	ErrAckDatapathVersionMismatch
	ErrAckTokenDecodeFailed
	ErrAckTokenExpired
	ErrAckSignatureMismatch
	ErrAckSharedKeyHashFailed
	ErrAckPublicKeyFailed

	// udp 3
	ErrUDPSynTokenFailed
	ErrUDPSynTokenTooSmall
	ErrUDPSynTokenEncodeFailed
	ErrUDPSynTokenHashFailed
	ErrUDPSynTokenSignFailed
	ErrUDPSynSharedSecretMissing
	ErrUDPSynInvalidSecret
	ErrUDPSynInvalidTokenLength
	ErrUDPSynMissingSignature
	ErrUDPSynInvalidSignature
	ErrUDPSynCompressedTagMismatch
	ErrUDPSynDatapathVersionMismatch
	ErrUDPSynTokenDecodeFailed
	ErrUDPSynTokenExpired
	ErrUDPSynSignatureMismatch
	ErrUDPSynSharedKeyHashFailed
	ErrUDPSynPublicKeyFailed

	ErrUDPSynAckTokenFailed
	ErrUDPSynAckTokenTooSmall
	ErrUDPSynAckTokenEncodeFailed
	ErrUDPSynAckTokenHashFailed
	ErrUDPSynAckTokenSignFailed
	ErrUDPSynAckSharedSecretMissing
	ErrUDPSynAckInvalidSecret
	ErrUDPSynAckInvalidTokenLength
	ErrUDPSynAckMissingSignature
	ErrUDPSynAckInvalidSignature
	ErrUDPSynAckCompressedTagMismatch
	ErrUDPSynAckDatapathVersionMismatch
	ErrUDPSynAckTokenDecodeFailed
	ErrUDPSynAckTokenExpired
	ErrUDPSynAckSignatureMismatch
	ErrUDPSynAckSharedKeyHashFailed
	ErrUDPSynAckPublicKeyFailed

	ErrUDPAckTokenFailed
	ErrUDPAckTokenTooSmall
	ErrUDPAckTokenEncodeFailed
	ErrUDPAckTokenHashFailed
	ErrUDPAckTokenSignFailed
	ErrUDPAckSharedSecretMissing
	ErrUDPAckInvalidSecret
	ErrUDPAckInvalidTokenLength
	ErrUDPAckMissingSignature
	ErrUDPAckInvalidSignature
	ErrUDPAckCompressedTagMismatch
	ErrUDPAckDatapathVersionMismatch
	ErrUDPAckTokenDecodeFailed
	ErrUDPAckTokenExpired
	ErrUDPAckSignatureMismatch
	ErrUDPAckSharedKeyHashFailed
	ErrUDPAckPublicKeyFailed
)
