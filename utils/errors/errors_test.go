package errors

import (
	"errors"
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var testErr *Error

func Test_NewError(t *testing.T) {

	Convey("Given I create an Error", t, func() {
		err := NewError("title", 400, "content")

		Convey("Then the data should be correct", func() {
			So(errors.As(err, &testErr), ShouldBeTrue)
			So(err.Title(), ShouldEqual, "title")
			So(err.Code(), ShouldEqual, 400)
			So(err.Content(), ShouldEqual, "content")
			So(err.CounterID(), ShouldEqual, -1)
		})
	})

	Convey("Given I create an Error with counter", t, func() {
		err := NewErrorWithCounter("title", 400, "content", 23)

		Convey("Then the data should be correct", func() {
			So(errors.As(err, &testErr), ShouldBeTrue)
			So(err.Title(), ShouldEqual, "title")
			So(err.Code(), ShouldEqual, 400)
			So(err.Content(), ShouldEqual, "content")
			So(err.CounterID(), ShouldEqual, 23)
		})
	})
}

type testErrorStr struct {
	err interface{}
}

func (t *testErrorStr) Error() string {
	return ""
}

func Test_WrapUnwrapError(t *testing.T) {

	Convey("Given I create an Error with counter", t, func() {
		err := NewErrorWithCounter("title", 400, "content", 23)

		Convey("Then the data should be correct", func() {
			So(errors.As(err, &testErr), ShouldBeTrue)
			So(err.Title(), ShouldEqual, "title")
			So(err.Code(), ShouldEqual, 400)
			So(err.Content(), ShouldEqual, "content")
			So(err.CounterID(), ShouldEqual, 23)
		})

		Convey("Given I wrap errors", func() {

			type my1 struct{}
			type my2 struct{}

			err1 := errors.New("error1")
			err2 := Wrap(err1)
			err3 := err2.(*Error).Wrap(&testErrorStr{my1{}})
			err4 := Wrap(err3)
			err5 := err4.(*Error).Wrap(&testErrorStr{my2{}})

			Convey("Then the data should be correct", func() {
				fmt.Println("ERROR", errors.Unwrap(err3))
				So(errors.As(err5, &testErr), ShouldBeTrue)

			})
		})
	})
}
