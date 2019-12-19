package nfqparser

import (
	"fmt"
	"io/ioutil"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	testFilePath = "/tmp/nfqdrops"
)

func init() {
	testCreateFile()
}

func testProperLayout() *NFQLayout {

	return &NFQLayout{
		QueueNum:     "6",
		PeerPortID:   "4025478776",
		QueueTotal:   "0",
		CopyMode:     "2",
		CopyRange:    "65531",
		QueueDropped: "0",
		UserDropped:  "0",
		IDSequence:   "3",
	}
}

func testCreateFile() {

	if err := ioutil.WriteFile(testFilePath, []byte(testNFQData), 0777); err != nil {
		panic(err)
	}
}

func TestNFQParserRetrieveByQueue(t *testing.T) {

	Convey("Given I create a new nfqparser instance", t, func() {
		nfqParser := NewNFQParser()
		nfqParser.filePath = testFilePath

		Convey("Given I try to synchronize data", func() {
			err := nfqParser.Synchronize()

			Convey("Then I should not get any errors", func() {
				So(err, ShouldBeNil)
			})

			Convey("Given I try to retrieve data for a queue", func() {
				queueData := nfqParser.RetrieveByQueue("6")

				Convey("Then queue data should match", func() {
					So(queueData, ShouldResemble, testProperLayout())
				})
			})

			Convey("Given I try to retrieve data for a queue and compare a specific field", func() {
				queueData := nfqParser.RetrieveByQueue("6")

				Convey("Then queue data should match", func() {
					So(queueData.CopyRange, ShouldEqual, testProperLayout().CopyRange)
				})
			})

			Convey("Given I try to retrieve data for a queue with different expected data", func() {
				queueData := nfqParser.RetrieveByQueue("1")

				Convey("Then queue data should match", func() {
					So(queueData, ShouldNotResemble, testProperLayout())
				})
			})

			Convey("Given I try to retrieve data for a invalid queue num", func() {
				queueData := nfqParser.RetrieveByQueue("9")

				Convey("Then queue data should match", func() {
					So(queueData, ShouldBeNil)
				})
			})
		})
	})
}

func TestNFQParserRetrieveAll(t *testing.T) {

	Convey("Given I create a new nfqparser instance", t, func() {
		nfqParser := NewNFQParser()
		nfqParser.filePath = testFilePath

		Convey("Given I try to synchronize data", func() {
			err := nfqParser.Synchronize()

			Convey("Then I should not get any errors", func() {
				So(err, ShouldBeNil)
			})

			Convey("Given I try to retrieve all", func() {
				queueData := nfqParser.RetrieveAll()

				Convey("Then length of queue data should be equal", func() {
					So(len(queueData), ShouldEqual, 8)
				})
			})
		})
	})
}

func TestNFQParserString(t *testing.T) {

	Convey("Given I create a new nfqparser instance", t, func() {
		nfqParser := NewNFQParser()
		nfqParser.filePath = testFilePath

		Convey("Given I try to synchronize data", func() {
			err := nfqParser.Synchronize()

			Convey("Then I should not get any errors", func() {
				So(err, ShouldBeNil)
			})

			Convey("Given I try to get string representation", func() {
				strData := nfqParser.String()

				Convey("Then queue data should match", func() {
					So(strData, ShouldEqual, testNFQData)
				})
			})

			Convey("Given I try to retrieve data for a queue with different expected data", func() {
				queueData := nfqParser.RetrieveByQueue("6")

				Convey("Then queue data should match", func() {
					So(queueData, ShouldResemble, testProperLayout())
				})

				Convey("Given I try to get string representation of particular queue number", func() {
					queueData := nfqParser.RetrieveByQueue("6")

					Convey("Then queue data should match", func() {
						So(queueData.String(), ShouldEqual, fmt.Sprintf("%v", testProperLayout()))
					})
				})

				Convey("Given I try to get string representation of empty layout, it should not panic", func() {
					nfqParser := NewNFQParser()
					str := nfqParser.RetrieveByQueue("6").String()

					Convey("Then queue data should match", func() {
						So(str, ShouldEqual, "")
					})
				})
			})
		})
	})
}
