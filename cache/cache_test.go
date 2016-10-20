package cache

import (
	"testing"

	"github.com/satori/go.uuid"
	. "github.com/smartystreets/goconvey/convey"
)

func customRefresh(val interface{}) interface{} {
	return val
}

func TestConstructorNewCache(t *testing.T) {
	Convey("Given I call the method NewCache, I should a new cache", t, func() {

		c := &Cache{}

		So(NewCache(customRefresh), ShouldHaveSameTypeAs, c)
	})
}

func TestElements(t *testing.T) {
	c := NewCache(nil)
	id := uuid.NewV4()
	fakeid := uuid.NewV4()
	newid := uuid.NewV4()
	value := "element"
	secondValue := "element2"

	Convey("Given that I want to test elemenets, I must initialize a cache", t, func() {

		// Test Write
		Convey("Given that I add a new element in the cache, it should not have errors", func() {
			err := c.Add(id, value)
			So(err, ShouldEqual, nil)
		})

		Convey("Given that I add the same element for a second time, I should get an error", func() {
			err := c.Add(id, value)
			So(err, ShouldNotEqual, nil)
		})

		// Test Read
		Convey("Given that I have an element in the cache, I should be able to read it", func() {
			newvalue, err := c.Get(id)
			So(value, ShouldEqual, newvalue)
			So(err, ShouldEqual, nil)
		})

		Convey("Given that I try to read an element that is not there, I should get an error", func() {
			_, err := c.Get(fakeid)
			So(err, ShouldNotEqual, nil)
		})

		// Test Update
		Convey("Given that I want to update the element, I should be able to do it", func() {

			err := c.Update(id, secondValue)
			So(err, ShouldEqual, nil)
			newvalue, err := c.Get(id)
			So(newvalue, ShouldEqual, secondValue)
			So(err, ShouldEqual, nil)
		})

		Convey("Given that I try to update an element that doesn't exist, I should get an error ", func() {
			nextid := uuid.NewV4()
			err := c.Update(nextid, value)
			So(err, ShouldNotEqual, nil)
		})

		Convey("Given that I try to add or update an element in the cache, I should not get an error", func() {

			err := c.AddOrUpdate(newid, secondValue)
			So(err, ShouldEqual, nil)
			newvalue, err := c.Get(newid)
			So(newvalue, ShouldEqual, secondValue)
			So(err, ShouldEqual, nil)
		})

		Convey("Given that I have an element in the cache, I should be able to delete it", func() {
			err := c.Remove(id)
			So(err, ShouldEqual, nil)
		})

		Convey("Given that I try to delete the same element twice, I should not be able to do it", func() {
			err := c.Remove(id)
			So(err, ShouldNotEqual, nil)
		})

		Convey("Given that I want do a default refresh, update all entries", func() {
			c.Refresh(0)
			newvalue, err := c.Get(newid)
			So(newvalue, ShouldEqual, secondValue)
			So(err, ShouldEqual, nil)
		})

	})
}
