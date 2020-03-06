package indexallocator

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAllocator(t *testing.T) {

	Convey("Given I do a new with size and start index", t, func() {
		indexes, size, startIndex := New(10, 10)
		So(size, ShouldEqual, 10)
		So(startIndex, ShouldEqual, 10)
		So(len(indexes.(*allocator).availableMarks), ShouldEqual, size)
		Convey("If i call New Again with a different size we get the original start back", func() {
			newIndex, newSize, newStartIndex := New(11, 11)
			So(newStartIndex, ShouldEqual, 10)
			So(newSize, ShouldEqual, 10)
			So(len(newIndex.(*allocator).availableMarks), ShouldEqual, size)
		})
		Convey("If i call get on this index allocator", func() {
			index := indexes.Get()
			So(index, ShouldNotEqual, -1)
			So(len(indexes.(*allocator).availableMarks), ShouldEqual, size-1)
			err := indexes.Put(index)
			So(err, ShouldBeNil)
			So(len(indexes.(*allocator).availableMarks), ShouldEqual, size)
		})
		Convey("Convey if i get all indexes out of this allocator", func() {
			retrievedIndexes := make([]int, size)
			for i := 0; i < size; i++ {
				retrievedIndexes[i] = indexes.Get()
				So(retrievedIndexes[i], ShouldNotEqual, -1)
			}
			Convey("If i call get on this empty range i get -1 and get no error when i put back", func() {
				errorIndex := indexes.Get()
				So(errorIndex, ShouldEqual, -1)
				for j := 0; j < size; j++ {
					err := indexes.Put(retrievedIndexes[j])
					So(err, ShouldBeNil)
				}
			})

		})
		Convey("When i call put with an invalid number i get an error ", func() {
			err := indexes.Put(startIndex + size + 1)
			So(err, ShouldNotBeNil)
			err = indexes.Put(startIndex - 1)
			So(err, ShouldNotBeNil)
		})
		Convey("When i try to insert a duplicate number it does not return an error", func() {
			err := indexes.Put(startIndex)
			So(err, ShouldBeNil)
		})
	})
}
