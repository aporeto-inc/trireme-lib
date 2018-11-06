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
		IDSequene:    "3",
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

func TestNFQParserRetrieveByField(t *testing.T) {

	Convey("Given I create a new nfqparser instance", t, func() {
		nfqParser := NewNFQParser()
		nfqParser.filePath = testFilePath

		Convey("Given I try to synchronize data", func() {
			err := nfqParser.Synchronize()

			Convey("Then I should not get any errors", func() {
				So(err, ShouldBeNil)
			})

			Convey("Given I try to retrieve data for a portid", func() {
				portID := nfqParser.RetrieveByField(FieldPeerPortID)

				Convey("Then portID should match", func() {
					So(portID, ShouldEqual, "132063333107750388139856926337506853605545056347323018840254787762806986372")
				})
			})

			Convey("Given I try to retrieve data for a id sequence", func() {
				portID := nfqParser.RetrieveByField(FieldIDSequene)

				Convey("Then id sequence should match", func() {
					So(portID, ShouldEqual, "00100231")
				})
			})

			Convey("Given I try to retrieve unknown field", func() {
				unknown := nfqParser.RetrieveByField(Field(35))

				Convey("Then queue data should match", func() {
					So(unknown, ShouldEqual, "Unknown field")
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

				Convey("Given I try to get string representaion of particular queue number", func() {
					queueData := nfqParser.RetrieveByQueue("6")

					Convey("Then queue data should match", func() {
						So(queueData.String(), ShouldEqual, fmt.Sprintf("%s", testProperLayout()))
					})
				})
			})
		})
	})
}
