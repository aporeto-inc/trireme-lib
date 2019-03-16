package policy

import "fmt"

// ErrorReason is the reason for an error
type ErrorReason string

const (
	// PUNotFound error reason
	PUNotFound ErrorReason = "PUNotFound"
)

var policyErrorDescription = map[ErrorReason]string{
	PUNotFound: "unable to find PU with specificed ID",
}

// Error is a specific error type for context
type Error struct {
	puID   string
	reason ErrorReason
}

func (e *Error) Error() string {
	desc, ok := policyErrorDescription[e.reason]
	if !ok {
		return fmt.Sprintf("%s (ID: %s)", e.reason, e.puID)
	}
	return fmt.Sprintf("%s (ID: %s): %s", e.reason, e.puID, desc)
}

// ErrPUNotFound creates a new context not found error
func ErrPUNotFound(puID string) error {
	return &Error{
		puID:   puID,
		reason: PUNotFound,
	}
}

// IsErrPUNotFound checks if this error is a context not found error
func IsErrPUNotFound(err error) bool {
	switch t := err.(type) {
	case *Error:
		return t.reason == PUNotFound
	default:
		return false
	}
}
