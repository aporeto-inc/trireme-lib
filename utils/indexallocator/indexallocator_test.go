package indexallocator

import (
	"sync"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var testLock sync.Mutex

func TestNew(t *testing.T) {
	testLock.Lock()
	defer testLock.Unlock()
	Convey("Given I do a new with size and start index", t, func() {
		indexes, size, startIndex := New(10, 10)
		So(size, ShouldEqual, 10)
		So(startIndex, ShouldEqual, 10)
		So(len(indexes.(*allocator).indexChannel), ShouldEqual, size)
		Convey("If i call New Again with a different size we get the original start back", func() {
			newIndex, newSize, newStartIndex := New(11, 11)
			So(newStartIndex, ShouldEqual, 10)
			So(newSize, ShouldEqual, 10)
			So(len(newIndex.(*allocator).indexChannel), ShouldEqual, newSize)
		})
	})
}

func TestGet(t *testing.T) {
	testLock.Lock()
	defer testLock.Unlock()
	Convey("Given i create a new IndexAllocator", t, func() {
		indexes, size, startIndex := New(10, 10)
		So(size, ShouldEqual, 10)
		So(startIndex, ShouldEqual, 10)
		So(len(indexes.(*allocator).indexChannel), ShouldEqual, size)
		Convey("I Get an index ", func() {
			firstIndex := indexes.Get()
			So(firstIndex, ShouldEqual, startIndex)
			So(len(indexes.(*allocator).indexChannel), ShouldEqual, size-1)
			secondIndex := indexes.Get()
			So(secondIndex, ShouldEqual, startIndex+1)
			So(len(indexes.(*allocator).indexChannel), ShouldEqual, size-2)
			Convey("I Put the index back", func() {
				indexes.Put(firstIndex)
				So(len(indexes.(*allocator).indexChannel), ShouldEqual, size-1)
			})

		})

	})
}
