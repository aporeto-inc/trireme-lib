package provider

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	mangle      = "mangle"
	inputChain  = "INPUT"
	outputChain = "OUTPUT"
)

func NewTestProvider(batchTables []string) *BatchProvider {
	batchTablesMap := map[string]bool{}
	for _, t := range batchTables {
		batchTablesMap[t] = true
	}
	return &BatchProvider{
		rules:       map[string]map[string][]string{},
		batchTables: batchTablesMap,
	}
}

func TestAppend(t *testing.T) {
	Convey("Given a valid batch provider", t, func() {
		p := NewTestProvider([]string{mangle})
		Convey("When I append a first rule, it should create the table", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
		})

		Convey("When I append two rules in the array, the values should be ordered ", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			err = p.Append(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			rules := p.rules[mangle][inputChain]
			So(rules[0], ShouldResemble, "val1")
			So(rules[1], ShouldResemble, "val2")
		})

		Convey("When I append two rules in different chains, there should be two chains", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			err = p.Append(mangle, outputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 2)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(len(p.rules[mangle][outputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
			So(p.rules[mangle][outputChain][0], ShouldResemble, "val2")
		})
	})
}

func TestInsert(t *testing.T) {
	Convey("Given a valid batch provider", t, func() {
		p := NewTestProvider([]string{mangle})
		Convey("When I insert a first rule, it should create the table", func() {
			err := p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
		})

		Convey("When I insert two rules in the first position of the array, the values should be reverse ordered ", func() {
			err := p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, inputChain, 1, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			rules := p.rules[mangle][inputChain]
			So(rules[1], ShouldResemble, "val1")
			So(rules[0], ShouldResemble, "val2")
		})

		Convey("When I insert two rules in the first and last position of the array ", func() {
			err := p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, inputChain, 2, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			rules := p.rules[mangle][inputChain]
			So(rules[0], ShouldResemble, "val1")
			So(rules[1], ShouldResemble, "val2")
		})

		Convey("When I insert two rules in the first and a bad position in the array, the last one should be last ", func() {
			err := p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, inputChain, 6, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			rules := p.rules[mangle][inputChain]
			So(rules[0], ShouldResemble, "val1")
			So(rules[1], ShouldResemble, "val2")
		})

		Convey("When I insert a rule in the midle of the array, it should go in the right place ", func() {
			err := p.Insert(mangle, inputChain, 1, "val3")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, inputChain, 1, "val2")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, inputChain, 2, "val1-2")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, inputChain, 4, "val2-3")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 5)
			rules := p.rules[mangle][inputChain]
			So(rules[0], ShouldResemble, "val1")
			So(rules[1], ShouldResemble, "val1-2")
			So(rules[2], ShouldResemble, "val2")
			So(rules[3], ShouldResemble, "val2-3")
			So(rules[4], ShouldResemble, "val3")
		})

		Convey("When I Insert two rules in different chains, there should be two chains", func() {
			err := p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, outputChain, 1, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 2)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(len(p.rules[mangle][outputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
			So(p.rules[mangle][outputChain][0], ShouldResemble, "val2")
		})
	})
}

func TestDelete(t *testing.T) {
	Convey("Given a valid batch provider", t, func() {
		p := NewTestProvider([]string{mangle})
		Convey("When I have one rule, I should be able to delete it", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
			err = p.Delete(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 0)
		})

		Convey("When I have two rules, I should be able to delete the second one", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			err = p.Append(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
			So(p.rules[mangle][inputChain][1], ShouldResemble, "val2")
			err = p.Delete(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
		})

		Convey("When I have two rules, I should be able to delete the first one", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			err = p.Append(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
			So(p.rules[mangle][inputChain][1], ShouldResemble, "val2")
			err = p.Delete(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val2")
		})

		Convey("When I have three rules, I should be able to delete the middle one", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			err = p.Append(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			err = p.Append(mangle, inputChain, "val3")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 3)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
			So(p.rules[mangle][inputChain][1], ShouldResemble, "val2")
			So(p.rules[mangle][inputChain][2], ShouldResemble, "val3")
			err = p.Delete(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
			So(p.rules[mangle][inputChain][1], ShouldResemble, "val3")
		})
	})
}

func TestClearChain(t *testing.T) {
	Convey("Given a valid batch provider", t, func() {
		p := NewTestProvider([]string{mangle})
		Convey("If a clear an empty chain, I should get no error", func() {
			err := p.ClearChain(mangle, inputChain)
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 0)
		})
		Convey("After I append a rule, I should be able to delete the chain", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "val1")
			err = p.ClearChain(mangle, inputChain)
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 0)
		})
	})
}

func TestDeleteChain(t *testing.T) {
	Convey("Given a valid batch provider", t, func() {
		p := NewTestProvider([]string{mangle})
		Convey("If a delete an empty chain, I should get no error", func() {
			err := p.ClearChain(mangle, inputChain)
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 0)
		})
		Convey("After I append a rule, I should be able to delete the chain", func() {
			err := p.NewChain(mangle, inputChain)
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 0)

			err = p.DeleteChain(mangle, inputChain)
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 0)
		})
	})
}
