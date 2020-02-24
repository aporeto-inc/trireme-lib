package errors

import (
	"fmt"
)

type Error struct {
	Title     string
	Subject   string
	Code      int
	CounterID int
	Content   string
	Data      interface{}
}

var _ error = &Error{}

func NewError(title string, subject string, code int, content string) *Error {

	return NewErrorWithCounter(title, subject, code, content, -1)
}

func NewErrorWithCounter(title string, subject string, code int, content string, counterID int) *Error {

	return &Error{
		Title:     title,
		Subject:   subject,
		Code:      code,
		CounterID: counterID,
		Content:   content,
	}
}

func (te *Error) Error() string {

	if te.CounterID != -1 {
		return fmt.Sprintf("error %d (%s): %s: %s: %d", te.Code, te.Title, te.Subject, te.Content, te.CounterID)
	}

	return fmt.Sprintf("error %d (%s): %s: %s", te.Code, te.Title, te.Subject, te.Content)
}

func Code(err error) int {

	te, ok := err.(*Error)
	if !ok {
		return 500
	}

	return te.Code
}
