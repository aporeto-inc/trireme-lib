// +build !windows

package policy

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNewTagStore(t *testing.T) {
	Convey("When I create a new Tagstore", t, func() {
		t := NewTagStore()
		Convey("It should not be nil", func() {
			So(t, ShouldNotBeNil)
		})
	})
}

func TestNewTagStoreFromMap(t *testing.T) {
	Convey("When I create a new tagstore from a map", t, func() {
		t := NewTagStoreFromMap(map[string]string{
			"app":   "web",
			"image": "nginx",
		})

		Convey("I should have the right store", func() {
			So(t, ShouldNotBeNil)
			tags := t.GetSlice()

			So(len(tags), ShouldEqual, 2)
			So(tags, ShouldContain, "app=web")
			So(tags, ShouldContain, "image=nginx")
		})
	})
}

func TestMerge(t *testing.T) {
	Convey("When I create a new tagstore from a map", t, func() {
		t := NewTagStoreFromMap(map[string]string{
			"app":   "web",
			"image": "nginx",
		})

		Convey("When I merge another store", func() {
			So(t, ShouldNotBeNil)
			m := NewTagStoreFromMap(map[string]string{
				"location": "somewhere",
			})
			So(m, ShouldNotBeNil)
			merged := t.Merge(m)
			So(merged, ShouldEqual, 1)

			tags := t.GetSlice()
			So(len(tags), ShouldEqual, 3)
			So(tags, ShouldContain, "app=web")
			So(tags, ShouldContain, "image=nginx")
			So(tags, ShouldContain, "location=somewhere")
		})
	})
}

func TestMergeCollision(t *testing.T) {
	Convey("When I create a new tagstore from a map", t, func() {
		t := NewTagStoreFromMap(map[string]string{
			"app":   "web",
			"image": "nginx",
		})

		Convey("When I merge another store with collisions", func() {
			So(t, ShouldNotBeNil)
			m := NewTagStoreFromMap(map[string]string{
				"app": "app",
			})
			So(m, ShouldNotBeNil)
			merged := t.Merge(m)
			So(merged, ShouldEqual, 0)

			tags := t.GetSlice()
			So(len(tags), ShouldEqual, 2)
			So(tags, ShouldContain, "app=web")
			So(tags, ShouldContain, "image=nginx")
		})
	})
}

func TestAllSettersGetters(t *testing.T) {
	Convey("When I create a new tagstore from a map", t, func() {
		ts := NewTagStoreFromMap(map[string]string{
			"app":   "web",
			"image": "nginx",
		})

		Convey("If I copy the tag store, it should be equal", func() {
			newstore := ts.Copy()
			So(newstore, ShouldNotBeNil)
			So(newstore, ShouldResemble, ts)
		})

		Convey("When I get a valid key, it should return the value", func() {
			value, ok := ts.Get("app")
			So(ok, ShouldBeTrue)
			So(value, ShouldResemble, "web")
		})

		Convey("When I get a non valid key, it should return false", func() {
			value, ok := ts.Get("randomkey")
			So(ok, ShouldBeFalse)
			So(value, ShouldEqual, "")
		})

		Convey("If I append a key/value pair, it should be in the store", func() {
			ts.AppendKeyValue("NewKey", "NewValue")
			value, ok := ts.Get("NewKey")
			So(ok, ShouldBeTrue)
			So(value, ShouldEqual, "NewValue")
		})

		Convey("If the store is corrupted", func() {
			ts.Tags = append(ts.Tags, "badtag")
			value, ok := ts.Get("randomeky")
			So(ok, ShouldBeFalse)
			So(value, ShouldEqual, "")
		})
	})
}
