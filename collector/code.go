package collector

const (
	// None represents no drop reason
	None = 0
	// FlowReject indicates that a flow was rejected
	FlowReject = 1
	// FlowAccept logs that a flow is accepted
	FlowAccept = 2
	// MissingToken indicates that the token was missing
	MissingToken = 3
	// InvalidToken indicates that the token was invalid
	InvalidToken = 4
	// InvalidFormat indicates that the packet metadata were not correct
	InvalidFormat = 5
	// InvalidHeader indicates that the TCP header was not there.
	InvalidHeader = 6
	// InvalidPayload indicates that the TCP payload was not there or bad.
	InvalidPayload = 7
	// InvalidContext indicates that there was no context in the metadata
	InvalidContext = 8
	// InvalidConnection indicates that there was no connection found
	InvalidConnection = 9
	// InvalidState indicates that a packet was received without proper state information
	InvalidState = 10
	// InvalidNonse indicates that the nonse check failed
	InvalidNonse = 11
	// PolicyDrop indicates that the flow is rejected because of the policy decision
	PolicyDrop = 12
	// APIPolicyDrop indicates that the request was dropped because of failed API validation.
	APIPolicyDrop = 13
	// UnableToDial indicates that the proxy cannot dial out the connection
	UnableToDial = 14
	// CompressedTagMismatch indicates that the compressed tag version is dissimilar
	CompressedTagMismatch = 15
	// EncryptionMismatch indicates that the policy encryption varies between client and server enforcer
	EncryptionMismatch = 16
	// DatapathVersionMismatch indicates that the datapath version is dissimilar
	DatapathVersionMismatch = 17
	// PacketDrop indicate a single packet drop
	PacketDrop = 18
)

func CodeToString(code int) string {

	switch code {

	case None:
		return ""

	case FlowReject:
		return "reject"

	case FlowAccept:
		return "accept"

	case MissingToken:
		return "missingtoken"

	case InvalidToken:
		return "token"

	case InvalidFormat:
		return "format"

	case InvalidHeader:
		return "header"

	case InvalidPayload:
		return "payload"

	case InvalidContext:
		return "context"

	case InvalidConnection:
		return "connection"

	case InvalidState:
		return "state"

	case InvalidNonse:
		return "nonse"

	case PolicyDrop:
		return "policy"

	case APIPolicyDrop:
		return "api"

	case UnableToDial:
		return "dial"

	case CompressedTagMismatch:
		return "compressedtagmismatch"

	case EncryptionMismatch:
		return "encryptionmismatch"

	case DatapathVersionMismatch:
		return "datapathversionmismatch"

	case PacketDrop:
		return "packetdrop"

	default:
		return ""
	}
}
