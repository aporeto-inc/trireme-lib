// +build !windows

package policy

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNewTagStore(t *testing.T) {
	Convey("When I create a new Tagstore", t, func() {
		t := NewTagStore()
		Convey("It should not be nil", func() {
			So(t, ShouldNotBeNil)
			So(t.IsEmpty(), ShouldEqual, true)
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
			t.Merge(m)

			tags := t.GetSlice()
			So(len(tags), ShouldEqual, 3)
			So(tags, ShouldContain, "app=web")
			So(tags, ShouldContain, "image=nginx")
			So(tags, ShouldContain, "location=somewhere")
		})
	})
}

func TestString(t *testing.T) {
	Convey("When I create a new tagstore the String() should match", t, func() {
		tags := []string{"app=web", "app=web1", "id", "image=nginx"}
		t := NewTagStoreFromSlice(tags)
		So(t.IsEmpty(), ShouldEqual, false)
		newTags := strings.Split(t.String(), " ")
		So(len(tags), ShouldEqual, len(newTags))
		for _, tag := range newTags {
			So(tags, ShouldContain, tag)
		}
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
			t.Merge(m)

			tags := t.GetSlice()
			So(len(tags), ShouldEqual, 2)
			So(tags, ShouldContain, "app=web")
			So(tags, ShouldContain, "image=nginx")
		})

		Convey("When I merge another store with duplicate keys", func() {
			So(t, ShouldNotBeNil)
			m := NewTagStoreFromSlice([]string{
				"fred",
				"app",
				"app=web2",
			})
			So(m, ShouldNotBeNil)
			t.Merge(m)

			tags := t.GetSlice()
			So(len(tags), ShouldEqual, 4)
			So(tags, ShouldContain, "fred")
			So(tags, ShouldContain, "app=web")
			So(tags, ShouldContain, "app=web2")
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
			tags := ts.GetSlice()
			tags = append(tags, "badtag")
			ts = NewTagStoreFromSlice(tags)
			value, ok := ts.Get("randomeky")
			So(ok, ShouldBeFalse)
			So(value, ShouldEqual, "")
		})
	})
}

func TestJsonMarshal(t *testing.T) {

	tags := []string{
		"app=web",
		"image=nginx",
		"fred",
	}

	Convey("When I create a new tagstore from a slice", t, func() {
		ts := NewTagStoreFromSlice(tags)

		bytes, err := json.Marshal(ts)
		So(err, ShouldBeNil)
		So(bytes, ShouldNotBeNil)

		newTS := &TagStore{}
		err = json.Unmarshal(bytes, newTS)
		So(err, ShouldBeNil)

		tags := newTS.GetSlice()
		So(len(tags), ShouldEqual, 3)
		So(tags, ShouldContain, "fred")
		So(tags, ShouldContain, "app=web")
		So(tags, ShouldContain, "image=nginx")

		// this test will make sure the tagstore is re-initialized
		newTS2 := NewTagStoreFromSlice([]string{"dummy"})
		err = json.Unmarshal(bytes, newTS2)
		So(err, ShouldBeNil)
		tags = newTS2.GetSlice()
		So(len(tags), ShouldEqual, 3)
		So(tags, ShouldContain, "fred")
		So(tags, ShouldContain, "app=web")
		So(tags, ShouldContain, "image=nginx")
	})
}

func TestGetKeys(t *testing.T) {
	Convey("When I create a new tagstore from a map", t, func() {
		t := NewTagStoreFromMap(map[string]string{
			"app":   "web",
			"image": "nginx",
		})

		keys := t.GetKeys()
		So(len(keys), ShouldEqual, 2)
		So(keys, ShouldContain, "app")
		So(keys, ShouldContain, "image")
	})
}

func TestRemoveKeys(t *testing.T) {
	Convey("When I create a new tagstore from a map", t, func() {
		t := NewTagStoreFromSlice([]string{
			"app=web",
			"app1=web",
			"image=nginx",
			"image=nginx1",
		})

		t.RemoveTagsByKeys([]string{"app", "image", "fred"})

		keys := t.GetKeys()
		So(len(keys), ShouldEqual, 1)
		So(keys, ShouldContain, "app1")
	})
}
