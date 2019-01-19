package tokens

import "go.aporeto.io/trireme-lib/collector"

const (
	errCompressedTagMismatch   = "Compressed tag mismatch"
	errDatapathVersionMismatch = "Datapath version mismatch"
)

// ErrTokens holds error message in string
type ErrTokens struct {
	message string
}

// newErrTokens returns ErrToken handle
func newErrTokens(message string) *ErrTokens {
	return &ErrTokens{
		message: message,
	}
}

// Error returns error in string
func (e *ErrTokens) Error() string {

	return e.message
}

// Reason returns collector reason
func (e *ErrTokens) Reason() string {

	switch e.message {
	case errCompressedTagMismatch:
		return collector.CompressedTagMismatch
	case errDatapathVersionMismatch:
		return collector.DatapathVersionMismatch
	default:
		return collector.InvalidToken
	}
}
