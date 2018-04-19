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

func TestNewTagStoreFromSlice(t *testing.T) {
	Convey("When I create a new tagstore from a map", t, func() {
		t := NewTagStoreFromSlice([]string{"app=web", "app=db", "image=nginx"})

		Convey("I should have the right store", func() {
			So(t, ShouldNotBeNil)
			tags := t.GetSlice()

			So(len(tags), ShouldEqual, 3)
			So(tags, ShouldContain, "app=web")
			So(tags, ShouldContain, "app=db")
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
		So(t, ShouldNotBeNil)

		Convey("When I merge another store", func() {
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
				"app": "web",
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
			value, ok := ts.GetValues("app")
			So(ok, ShouldBeTrue)
			So(value, ShouldResemble, []string{"web"})
			unique, uok := ts.GetUnique("app")
			So(uok, ShouldBeTrue)
			So(unique, ShouldResemble, "web")
		})

		Convey("When I get a non valid key, it should return false", func() {
			value, ok := ts.GetValues("randomkey")
			So(ok, ShouldBeFalse)
			So(len(value), ShouldEqual, 0)
		})

		Convey("If I append a key/value pair, it should be in the store", func() {
			ts.AppendKeyValue("NewKey", "NewValue")
			value, ok := ts.GetValues("NewKey")
			So(ok, ShouldBeTrue)
			So(value, ShouldContain, "NewValue")
		})

		Convey("If I append key/values with the same key and different values, they should be in the map", func() {
			ts.AppendKeyValue("key1", "value1")
			ts.AppendKeyValue("key1", "value2")
			value, ok := ts.GetValues("key1")
			So(ok, ShouldBeTrue)
			So(len(value), ShouldEqual, 2)
			So(value, ShouldContain, "value1")
			So(value, ShouldContain, "value2")

			Convey("And the Unique get should fail", func() {
				_, ok := ts.GetUnique("key1")
				So(ok, ShouldBeFalse)
			})
		})

		Convey("If the store is corrupted", func() {
			ts.tags = append(ts.tags, "badtag")
			value, ok := ts.GetValues("randomeky")
			So(ok, ShouldBeFalse)
			So(len(value), ShouldEqual, 0)
		})
	})
}
