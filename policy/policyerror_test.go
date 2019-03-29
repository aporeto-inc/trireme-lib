package policy

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestPolicyErrors(t *testing.T) {
	Convey("A manually constructed error object", t, func() {
		err := Error{
			puID:   "whatever",
			reason: ErrorReason("its-typed-for-a-reason"),
			err:    nil,
		}
		Convey("should still print a proper error message", func() {
			expected := "its-typed-for-a-reason whatever"
			So(err.Error(), ShouldEqual, expected)
		})
	})
	Convey("Creating error objects using their initializers for", t, func() {
		failure := fmt.Errorf("failure")
		Convey("ErrPUNotFound", func() {
			err := ErrPUNotFound("default/pod", failure)
			So(err, ShouldNotBeNil)
			Convey("should print an expected error message", func() {
				expected := fmt.Sprintf("%s %s: %s%s", PUNotFound, "default/pod", policyErrorDescription[PUNotFound], ": "+failure.Error())
				So(err.Error(), ShouldEqual, expected)
			})
			Convey("should successfully test against its probing function", func() {
				So(IsErrPUNotFound(err), ShouldBeTrue)
				So(IsErrPUNotFound(failure), ShouldBeFalse)
			})
		})
		Convey("ErrPUNotUnique", func() {
			err := ErrPUNotUnique("default/pod", failure)
			So(err, ShouldNotBeNil)
			Convey("should print an expected error message", func() {
				expected := fmt.Sprintf("%s %s: %s%s", PUNotUnique, "default/pod", policyErrorDescription[PUNotUnique], ": "+failure.Error())
				So(err.Error(), ShouldEqual, expected)
			})
			Convey("should successfully test against its probing function", func() {
				So(IsErrPUNotUnique(err), ShouldBeTrue)
				So(IsErrPUNotUnique(failure), ShouldBeFalse)
			})
		})
		Convey("ErrPUCreateFailed", func() {
			err := ErrPUCreateFailed("default/pod", failure)
			So(err, ShouldNotBeNil)
			Convey("should print an expected error message", func() {
				expected := fmt.Sprintf("%s %s: %s%s", PUCreateFailed, "default/pod", policyErrorDescription[PUCreateFailed], ": "+failure.Error())
				So(err.Error(), ShouldEqual, expected)
			})
			Convey("should successfully test against its probing function", func() {
				So(IsErrPUCreateFailed(err), ShouldBeTrue)
				So(IsErrPUCreateFailed(failure), ShouldBeFalse)
			})
		})
		Convey("ErrPUAlreadyActivated", func() {
			err := ErrPUAlreadyActivated("default/pod", failure)
			So(err, ShouldNotBeNil)
			Convey("should print an expected error message", func() {
				expected := fmt.Sprintf("%s %s: %s%s", PUAlreadyActivated, "default/pod", policyErrorDescription[PUAlreadyActivated], ": "+failure.Error())
				So(err.Error(), ShouldEqual, expected)
			})
			Convey("should successfully test against its probing function", func() {
				So(IsErrPUAlreadyActivated(err), ShouldBeTrue)
				So(IsErrPUAlreadyActivated(failure), ShouldBeFalse)
			})
		})
	})
}
