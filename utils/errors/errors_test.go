package errors

import (
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_NewError(t *testing.T) {

	Convey("Given I create an Error", t, func() {
		err := NewError("token", "decoding", 400, "token creation failed")

		Convey("Then the data should be correct", func() {
			So(err.Title, ShouldEqual, "token")
			So(err.Subject, ShouldEqual, "decoding")
			So(err.Code, ShouldEqual, 400)
			So(err.Content, ShouldEqual, "token creation failed")
			So(err.CounterID, ShouldEqual, -1)

			So(err.Error(), ShouldEqual, "error 400 (token): decoding: token creation failed")
		})
	})

	Convey("Given I create an Error with counter", t, func() {
		err := NewErrorWithCounter("token", "encoding", 400, "token creation failed", 23)

		Convey("Then the data should be correct", func() {
			So(err.Title, ShouldEqual, "token")
			So(err.Subject, ShouldEqual, "encoding")
			So(err.Code, ShouldEqual, 400)
			So(err.Content, ShouldEqual, "token creation failed")
			So(err.CounterID, ShouldEqual, 23)

			So(err.Error(), ShouldEqual, "error 400 (token): encoding: token creation failed: 23")
		})
	})
}

func Test_Code(t *testing.T) {

	Convey("Given I create a custom Error", t, func() {
		err := NewError("token", "decoding", 400, "token creation failed")

		Convey("Given I try to get code", func() {
			code := Code(err)

			Convey("Then the code should be correct", func() {
				So(code, ShouldEqual, 400)
			})
		})
	})

	Convey("Given I create an Error", t, func() {
		err := errors.New("token creation failed")

		Convey("Given I try to get code", func() {
			code := Code(err)

			Convey("Then the code should be correct", func() {
				So(code, ShouldEqual, 500)
			})
		})
	})

	Convey("Given I get code with nil error", t, func() {

		code := Code(nil)

		Convey("Then the code should be correct", func() {
			So(code, ShouldEqual, 500)
		})
	})
}
