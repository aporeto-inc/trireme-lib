package counters

import "sync"

// Counters holds the counters value.
type Counters struct {
	counters []uint32

	sync.RWMutex
}

// This should be multiples of 10.
const (
	totalCounters = 170
)

// CounterType custom counter error type.
type CounterType int

//go:generate stringer -type=CounterType -trimprefix Err
// WARNING: Append any new counters at the end of the list.
// DO NOT CHANGE EXISTING ORDER.
// Also ensure that the list doesn't exceed current totalCounters,
// If it does, increase the totalCounters by multiples of 10.
const (
	ErrUnknownError CounterType = iota
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
	ErrAppServicePreProcessorFailed
	ErrAppServicePostProcessorFailed
	ErrNetServicePreProcessorFailed
	ErrNetServicePostProcessorFailed
	ErrSynTokenFailed
	ErrSynDroppedInvalidToken
	ErrSynDroppedTCPOption
	ErrSynDroppedInvalidFormat
	ErrSynRejectPacket
	ErrSynUnexpectedPacket
	ErrInvalidNetSynState
	ErrNetSynNotSeen
	ErrSynToExtNetAccept
	ErrSynFromExtNetAccept
	ErrSynToExtNetReject
	ErrSynFromExtNetReject
	ErrSynAckTokenFailed
	ErrOutOfOrderSynAck
	ErrInvalidSynAck
	ErrSynAckInvalidToken
	ErrSynAckMissingToken
	ErrSynAckNoTCPAuthOption
	ErrSynAckInvalidFormat
	ErrSynAckEncryptionMismatch
	ErrSynAckRejected
	ErrSynAckToExtNetAccept
	ErrSynAckFromExtNetAccept
	ErrSynAckFromExtNetReject
	ErrAckTokenFailed
	ErrAckRejected
	ErrAckTCPNoTCPAuthOption //50
	ErrAckInvalidFormat
	ErrAckInvalidToken
	ErrAckInUnknownState
	ErrAckFromExtNetAccept
	ErrAckFromExtNetReject
	ErrUDPAppPreProcessingFailed
	ErrUDPAppPostProcessingFailed
	ErrUDPNetPreProcessingFailed
	ErrUDPNetPostProcessingFailed
	ErrUDPSynInvalidToken
	ErrUDPSynMissingClaims
	ErrUDPSynDroppedPolicy
	ErrUDPSynAckNoConnection
	ErrUDPSynAckPolicy
	ErrDroppedTCPPackets
	ErrDroppedUDPPackets
	ErrDroppedICMPPackets
	ErrDroppedDNSPackets
	ErrDroppedDHCPPackets
	ErrDroppedNTPPackets
	ErrTCPConnectionsExpired
	ErrUDPConnectionsExpired
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
	ErrSynSharedKeyHashFailed
	ErrSynPublicKeyFailed
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
	ErrSynAckSharedKeyHashFailed
	ErrSynAckPublicKeyFailed
	ErrAckTokenEncodeFailed
	ErrAckTokenHashFailed
	ErrAckTokenSignFailed
	ErrAckSharedSecretMissing
	ErrAckInvalidSecret
	ErrAckInvalidTokenLength
	ErrAckMissingSignature
	ErrAckCompressedTagMismatch
	ErrAckDatapathVersionMismatch
	ErrAckTokenDecodeFailed
	ErrAckTokenExpired
	ErrAckSignatureMismatch
	ErrUDPSynTokenFailed
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
	ErrUDPSynSharedKeyHashFailed
	ErrUDPSynPublicKeyFailed
	ErrUDPSynAckTokenFailed
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
	ErrUDPSynAckSharedKeyHashFailed
	ErrUDPSynAckPublicKeyFailed
	ErrUDPAckTokenFailed
	ErrUDPAckTokenEncodeFailed
	ErrUDPAckTokenHashFailed
	ErrUDPAckSharedSecretMissing
	ErrUDPAckInvalidSecret
	ErrUDPAckInvalidTokenLength
	ErrUDPAckMissingSignature
	ErrUDPAckCompressedTagMismatch
	ErrUDPAckDatapathVersionMismatch
	ErrUDPAckTokenDecodeFailed
	ErrUDPAckTokenExpired
	ErrUDPAckSignatureMismatch
	ErrAppSynAuthOptionSet
	ErrAckToFinAck
	ErrIgnoreFin
	ErrInvalidNetState
	ErrInvalidNetAckState
	ErrAppSynAckAuthOptionSet
	ErrDuplicateAckDrop
	ErrNfLogError
	errMax
)
