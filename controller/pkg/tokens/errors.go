package tokens

import "go.aporeto.io/trireme-lib/v11/collector"

const (
	errCompressedTagMismatch   = "Compressed tag mismatch"
	errDatapathVersionMismatch = "Datapath version mismatch"
)

// ErrToken holds error message in string
type ErrToken struct {
	message string
}

// newErrToken returns ErrToken handle
func newErrToken(message string) *ErrToken {
	return &ErrToken{
		message: message,
	}
}

// Error returns error in string
func (e *ErrToken) Error() string {

	return e.message
}

// Code returns collector reason
func (e *ErrToken) Code() string {

	switch e.message {
	case errCompressedTagMismatch:
		return collector.CompressedTagMismatch
	case errDatapathVersionMismatch:
		return collector.DatapathVersionMismatch
	default:
		return collector.InvalidToken
	}
}

// CodeFromErr returns the collector code from ErrToken
func CodeFromErr(err error) string {

	errToken, ok := err.(*ErrToken)
	if !ok {
		return collector.InvalidToken
	}

	return errToken.Code()
}
