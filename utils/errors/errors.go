package errors

import (
	"fmt"
)

// Error represents custom error.
type Error struct {
	Title     string
	Subject   string
	Code      int
	CounterID int
	Content   string
	Data      interface{}
}

var _ error = &Error{}

// NewError returns Error which implements error interface.
func NewError(title string, subject string, code int, content string) *Error {

	return NewErrorWithCounter(title, subject, code, content, -1)
}

// NewError returns Error which implements error interface with counters.
func NewErrorWithCounter(title string, subject string, code int, content string, counterID int) *Error {

	return &Error{
		Title:     title,
		Subject:   subject,
		Code:      code,
		CounterID: counterID,
		Content:   content,
	}
}

// Error return string representation of error.
func (te *Error) Error() string {

	if te.CounterID != -1 {
		return fmt.Sprintf("error %d (%s): %s: %s: %d", te.Code, te.Title, te.Subject, te.Content, te.CounterID)
	}

	return fmt.Sprintf("error %d (%s): %s: %s", te.Code, te.Title, te.Subject, te.Content)
}

// Code returns the code from error if it is of type Error else 500.
func Code(err error) int {

	te, ok := err.(*Error)
	if !ok {
		return 500
	}

	return te.Code
}
