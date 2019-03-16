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
	err    error
}

func (e *Error) Error() string {
	desc, ok := policyErrorDescription[e.reason]
	var err string
	if e.err != nil {
		err = ": " + e.err.Error()
	}
	if !ok {
		return fmt.Sprintf("%s (ID: %s)%s", e.reason, e.puID, err)
	}
	return fmt.Sprintf("%s (ID: %s): %s%s", e.reason, e.puID, desc, err)
}

// ErrPUNotFound creates a new context not found error
func ErrPUNotFound(puID string, err error) error {
	return &Error{
		puID:   puID,
		reason: PUNotFound,
		err:    err,
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
