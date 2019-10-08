package cache

import (
	"testing"
	"time"

	"github.com/rs/xid"
	. "github.com/smartystreets/goconvey/convey"
)

func TestConstructorNewCache(t *testing.T) {

	//	t.Parallel()

	Convey("Given I call the method NewCache, I should a new cache", t, func() {

		c := &Cache{
			name: "cache",
		}

		So(NewCache("cache"), ShouldHaveSameTypeAs, c)
	})
}

func TestElements(t *testing.T) {

	//	t.Parallel()

	c := NewCache("cache")
	id := xid.New()
	fakeid := xid.New()
	newid := xid.New()
	value := "element"
	secondValue := "element2"
	thirdValue := "element3"

	Convey("Given that I want to test elemenets, I must initialize a cache", t, func() {

		// Test Write
		Convey("Given that I add a new element in the cache, it should not have errors", func() {
			err := c.Add(id, value)
			So(err, ShouldBeNil)
		})

		Convey("Given that I add the same element for a second time, I should get an error", func() {
			err := c.Add(id, value)
			So(err, ShouldNotBeNil)
		})

		// Test Read
		Convey("Given that I have an element in the cache, I should be able to read it", func() {
			newvalue, err := c.Get(id)
			So(value, ShouldEqual, newvalue)
			So(err, ShouldBeNil)
		})

		Convey("Given that I try to read an element that is not there, I should get an error", func() {
			_, err := c.Get(fakeid)
			So(err, ShouldNotBeNil)
		})

		// Test Update
		Convey("Given that I want to update the element, I should be able to do it", func() {

			err := c.Update(id, secondValue)
			So(err, ShouldBeNil)
			newvalue, err := c.Get(id)
			So(newvalue, ShouldEqual, secondValue)
			So(err, ShouldBeNil)
		})

		Convey("Given that I try to update an element that doesn't exist, I should get an error ", func() {
			nextid := xid.New()
			err := c.Update(nextid, value)
			So(err, ShouldNotBeNil)
		})

		Convey("Given that I try to add or update an element in the cache, I should not get an error", func() {

			ok := c.AddOrUpdate(newid, secondValue)
			newvalue, err := c.Get(newid)
			So(newvalue, ShouldEqual, secondValue)
			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)
		})

		Convey("Given that I try to update an element in the cache, I should not get an error", func() {

			ok := c.AddOrUpdate(newid, thirdValue)
			newvalue, err := c.Get(newid)
			So(newvalue, ShouldEqual, thirdValue)
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)
		})

		Convey("Given that I have an element in the cache, I should be able to delete it", func() {
			err := c.Remove(id)
			So(err, ShouldBeNil)
		})

		Convey("Given that I try to delete the same element twice, I should not be able to do it", func() {
			err := c.Remove(id)
			So(err, ShouldNotBeNil)
		})
	})
}

func Test_CacheTimer(t *testing.T) {

	//t.Parallel()

	Convey("Given a new cache with an expiration timer ", t, func() {
		c := NewCacheWithExpiration("cache", 3*time.Second)

		Convey("When I create an item that has to exist for a second", func() {
			err := c.Add("key", "value")
			So(err, ShouldBeNil)

			Convey("Then I should be able to get back the item", func() {
				val, err := c.Get("key")
				So(err, ShouldBeNil)
				So(val.(string), ShouldResemble, "value")

				Convey("When I wait for 1 second and update the time", func() {
					<-time.After(1 * time.Second)

					c.AddOrUpdate("key", "value2")

					Convey("I should be able to read the second item", func() {
						val, err := c.Get("key")
						So(err, ShouldBeNil)
						So(val.(string), ShouldResemble, "value2")

						Convey("But when I wait for a another second, the items should still exist", func() {
							<-time.After(1 * time.Second)
							val, err := c.Get("key")
							So(err, ShouldBeNil)
							So(val.(string), ShouldResemble, "value2")

							Convey("But if I wait for two seconds after the update, the item must not exixt", func() {
								<-time.After(4 * time.Second)
								_, err := c.Get("key")
								So(err, ShouldNotBeNil)
							})
						})
					})

				})

			})
		})
	})
}

func add(a, b interface{}) interface{} {
	return a.(int) + b.(int)
}

func TestLockedModify(t *testing.T) {

	//t.Parallel()

	Convey("Given a new cache", t, func() {
		c := NewCache("cache")

		Convey("Given an element that is an integer", func() {
			err := c.Add("key", 1)
			So(err, ShouldBeNil)
			Convey("Given an an incremental add function", func() {
				value, err := c.LockedModify("key", add, 1)
				So(err, ShouldBeNil)
				So(value, ShouldNotBeNil)
				Convey("I should get the right value  ", func() {
					val, err := c.Get("key")
					So(err, ShouldBeNil)
					So(val.(int), ShouldEqual, 2)
				})
			})
		})
	})
}

func TestTimerExpirationWithUpdate(t *testing.T) {

	//t.Parallel()

	Convey("Given that I instantiate 1 objects with 2 second timers", t, func() {
		i := 1
		c := NewCacheWithExpiration("cache", 2*time.Second)
		err := c.Add(i, i)
		So(err, ShouldBeNil)
		Convey("When I check the cache size After 1 seconds, the size should be 1", func() {
			<-time.After(1 * time.Second)
			// So(c.SizeOf(), ShouldEqual, 1)
			Convey("When I update the object and check again after another 1 seconds, the size should be 1", func() {
				err := c.Update(1, 1)
				So(err, ShouldBeNil)
				<-time.After(1 * time.Second)
				// So(c.SizeOf(), ShouldEqual, 1) // @TODO: fix me it should be 1
				Convey("When I check the cache size After another 2 seconds, the size should be 0", func() {
					<-time.After(2 * time.Second)
					So(c.SizeOf(), ShouldBeZeroValue)
				})
			})
		})
	})
}

func TestGetReset(t *testing.T) {

	//t.Parallel()

	Convey("Given that I instantiate 1 object with a 2 second timer", t, func() {
		c := NewCacheWithExpiration("cache", 2*time.Second)
		err := c.Add("test", "test")
		So(err, ShouldBeNil)
		Convey("When I check the cache after 1 second, the element should be there", func() {
			<-time.After(1 * time.Second)
			d, err := c.Get("test")
			So(err, ShouldBeNil)
			So(d.(string), ShouldResemble, "test")

			Convey("When I retrieve the data with get reset", func() {

				val, err := c.GetReset("test", 0)
				So(err, ShouldBeNil)
				So(val.(string), ShouldResemble, "test")

				Convey("If I wait 1100, the data should still be there ", func() {
					<-time.After(1100 * time.Millisecond)
					d, err := c.Get("test")
					So(err, ShouldBeNil)
					So(d.(string), ShouldResemble, "test")

					Convey("If I wait for another second, the data should be gone", func() {
						<-time.After(1200 * time.Millisecond)
						val, err := c.Get("test")
						So(err, ShouldNotBeNil)
						So(val, ShouldBeNil)
					})
				})
			})
		})
	})
}

func TestSetTimeOut(t *testing.T) {

	//t.Parallel()

	Convey("Given that I instantiate 1 object with a 2 second timer", t, func() {
		c := NewCacheWithExpiration("cache", 2*time.Second)
		err := c.Add("test", "test")
		So(err, ShouldBeNil)
		Convey("When I check the cache after 1 second, the element should be there", func() {
			<-time.After(1 * time.Second)
			d, err := c.Get("test")
			So(err, ShouldBeNil)
			err = c.SetTimeOut("test", 2*time.Second)
			So(err, ShouldBeNil)
			So(d.(string), ShouldResemble, "test")

			Convey("When I reset the timer to two more seconds", func() {

				err := c.SetTimeOut("test", 2*time.Second)
				So(err, ShouldBeNil)

				Convey("If I wait 1100, the data should still be there ", func() {
					<-time.After(1500 * time.Millisecond)
					d, err := c.Get("test")
					So(err, ShouldBeNil)
					So(d.(string), ShouldResemble, "test")

					Convey("If I wait for another second, the data should be gone", func() {
						<-time.After(1200 * time.Millisecond)
						val, err := c.Get("test")
						So(err, ShouldNotBeNil)
						So(val, ShouldBeNil)
					})
				})
			})
		})
	})
}

func TestCacheWithExpirationNotifier(t *testing.T) {

	//t.Parallel()

	finished := make(chan bool)

	Convey("Given a cache with an expiration notitifier ", t, func() {
		c := NewCacheWithExpirationNotifier("cache", 2*time.Second, func(s DataStore, id interface{}, item interface{}) {
			if id.(string) == "test" && item.(string) == "test" {
				finished <- true
			} else {
				finished <- false
			}
		})

		Convey("When I add an element", func() {
			oldtime := time.Now()
			err := c.Add("test", "test")
			So(err, ShouldBeNil)
			Convey("I should receive a notification", func() {
				r := <-finished
				Duration := time.Since(oldtime)
				So(r, ShouldBeTrue)
				So(Duration.Seconds(), ShouldBeGreaterThanOrEqualTo, 2.0)
			})
		})
	})
}

func TestThousandsOfTimers(t *testing.T) {

	//t.Parallel()

	Convey("Given that I instantiate 10K objects with 2 second timers", t, func() {
		c := NewCacheWithExpiration("cache", 2*time.Second)
		for i := 0; i < 1000; i++ {
			err := c.Add(i, i)
			So(err, ShouldBeNil)
		}
		Convey("After I wait for 1 second and add 10K more objects with 2 second timers", func() {
			<-time.After(1 * time.Second)
			for i := 20000; i < 30000; i++ {
				err := c.Add(i, i)
				So(err, ShouldBeNil)
			}
			//TODO: This test is failing if we wait 3 seconds
			Convey("After I wait for another 4 seconds", func() {
				<-time.After(5 * time.Second)
				Convey("I should have no objects in the cache", func() {
					So(c.SizeOf(), ShouldEqual, 0)
				})
			})
		})
	})
}

func TestRemoveWithDelay(t *testing.T) {
	Convey("Given an initial cache that is non empty", t, func() {
		c := NewCache("cache")
		c.Add("info1", "info1") // nolint
		c.Add("info2", "info2") // nolint
		c.Add("info3", "info3") // nolint
		c.Add("info4", "info4") // nolint

		Convey("When I remove an valid entry with a duration of -1", func() {
			err := c.RemoveWithDelay("info1", -1)
			Convey("It should remove the entry right away", func() {
				So(err, ShouldBeNil)
				So(c.SizeOf(), ShouldEqual, 3)
				_, err := c.Get("info1")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I remove an valid entry with a duration of 2 seconds", func() {
			err := c.RemoveWithDelay("info2", 2*time.Second)
			Convey("It should remove the entry right away", func() {
				So(err, ShouldBeNil)
				So(c.SizeOf(), ShouldEqual, 4)
				<-time.After(3 * time.Second)
				So(c.SizeOf(), ShouldEqual, 3)
				_, err := c.Get("info2")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I remove an unknown entry with a duration of 2 seconds", func() {
			err := c.RemoveWithDelay("unknown", 2*time.Second)
			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}
