package errors

import (
	"fmt"
)

type Error struct {
	title     string
	code      int
	counterID int
	content   string

	Err error
}

var _ error = &Error{}

func NewError(title string, code int, content string) *Error {

	return NewErrorWithCounter(title, code, content, -1)
}

func NewErrorWithCounter(title string, code int, content string, counterID int) *Error {

	return &Error{
		title:     title,
		code:      code,
		counterID: counterID,
		content:   content,
	}
}

func (te *Error) Error() string {
	return fmt.Sprintf("this is error")
}

func (te *Error) Title() string {
	return te.title
}

func (te *Error) Code() int {
	return te.code
}

func (te *Error) Content() string {
	return te.content
}

func (te *Error) CounterID() int {
	return te.counterID
}

func (te *Error) Wrap(err error) error {
	return fmt.Errorf("%w %w", te.Err, err)
}

func Wrap(err error) error {

	return &Error{
		Err: err,
	}
}
