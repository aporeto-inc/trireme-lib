package provider

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/magiconair/properties/assert"
	. "github.com/smartystreets/goconvey/convey"
)

const (
	mangle      = "mangle"
	nat         = "nat"
	inputChain  = "INPUT"
	outputChain = "OUTPUT"
)

// Fake iptables controller that always returns succes.
type baseIpt struct{}

// Append apends a rule to chain of table
func (b *baseIpt) Append(table, chain string, rulespec ...string) error { return nil }

// Insert inserts a rule to a chain of table at the required pos
func (b *baseIpt) Insert(table, chain string, pos int, rulespec ...string) error { return nil }

// Delete deletes a rule of a chain in the given table
func (b *baseIpt) Delete(table, chain string, rulespec ...string) error { return nil }

// ListChains lists all the chains associated with a table
func (b *baseIpt) ListChains(table string) ([]string, error) { return nil, nil }

// ClearChain clears a chain in a table
func (b *baseIpt) ClearChain(table, chain string) error { return nil }

// DeleteChain deletes a chain in the table. There should be no references to this chain
func (b *baseIpt) DeleteChain(table, chain string) error { return nil }

// NewChain creates a new chain
func (b *baseIpt) NewChain(table, chain string) error { return nil }

// failingIpt iptables implementation that always fails (i.e. system failure)
type failingIpt struct{ baseIpt }

func (failingIpt) ListChains(table string) ([]string, error) {
	return []string{}, errors.New("iptables not found")
}

// emptyListIpt iptables implementation that returns an empty string
type emptyListIpt struct{ baseIpt }

func (emptyListIpt) ListChains(table string) ([]string, error) {
	return []string{}, nil
}

// emptySystemListIpt iptables implementation that returns an empty system iptables from 'sudo iptables -t mangle -S'
type emptySystemListIpt struct{ baseIpt }

func (emptySystemListIpt) ListChains(table string) ([]string, error) {
	var output []string

	if table == mangle {
		// mangle table
		output = []string{
			"-P PREROUTING ACCEPT",
			"-P INPUT ACCEPT",
			"-P FORWARD ACCEPT",
			"-P OUTPUT ACCEPT",
			"-P POSTROUTING ACCEPT",
		}
	} else {
		// nat table
		output = []string{
			"-P PREROUTING ACCEPT",
			"-P INPUT ACCEPT",
			"-P OUTPUT ACCEPT",
			"-P POSTROUTING ACCEPT",
		}
	}

	var chains []string
	for _, val := range output {
		if strings.HasPrefix(val, "-P") || strings.HasPrefix(val, "-N") {
			chains = append(chains, strings.Fields(val)[1])
		} else {
			break
		}
	}
	return chains, nil

}

// validSystemListIpt iptables implementation that returns a valid rules list from 'sudo iptables -t mangle -S'
type validSystemListIpt struct{ baseIpt }

func (validSystemListIpt) ListChains(table string) ([]string, error) {
	var output []string

	if table == mangle {
		// mangle table
		output = []string{
			"-P PREROUTING ACCEPT",
			"-P INPUT ACCEPT",
			"-P FORWARD ACCEPT",
			"-P OUTPUT ACCEPT",
			"-P POSTROUTING ACCEPT",
			"-N Tri-APP",
			"-A INPUT -s 10.8.0.0/24 -j DROP",
		}
	} else {
		// nat table
		output = []string{
			"-P PREROUTING ACCEPT",
			"-P INPUT ACCEPT",
			"-P OUTPUT ACCEPT",
			"-P POSTROUTING ACCEPT",
			"-A OUTPUT -p tcp -m tcp --dport 11111 -j DNAT --to-destination 1.1.1.1:80",
		}
	}

	var chains []string
	for _, val := range output {
		if strings.HasPrefix(val, "-P") || strings.HasPrefix(val, "-N") {
			chains = append(chains, strings.Fields(val)[1])
		} else {
			break
		}
	}
	return chains, nil
}

func NewTestProvider(batchTables []string, quote bool) *BatchProvider {
	p := NewCustomBatchProvider(nil, nil, batchTables)
	p.commitFunc = func(buf *bytes.Buffer) error { return nil }
	p.quote = quote
	return p
}

func TestAppend(t *testing.T) {
	Convey("Given a valid batch provider", t, func() {
		p := NewTestProvider([]string{mangle}, true)
		So(p, ShouldNotBeNil)

		Convey("When I append a first rule, it should create the table", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
		})

		Convey("When I append two rules in the array, the values should be ordered ", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			err = p.Append(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			rules := p.rules[mangle][inputChain]
			So(rules[0], ShouldResemble, "\"val1\"")
			So(rules[1], ShouldResemble, "\"val2\"")
		})

		Convey("When I append two rules in different chains, there should be two chains", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			err = p.Append(mangle, outputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 2)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(len(p.rules[mangle][outputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
			So(p.rules[mangle][outputChain][0], ShouldResemble, "\"val2\"")
		})
	})
}

func TestInsert(t *testing.T) {
	Convey("Given a valid batch provider", t, func() {
		p := NewTestProvider([]string{mangle}, true)
		So(p, ShouldNotBeNil)

		Convey("When I insert a first rule, it should create the table", func() {
			err := p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
		})

		Convey("When I insert two rules in the first position of the array, the values should be reverse ordered ", func() {
			err := p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, inputChain, 1, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			rules := p.rules[mangle][inputChain]
			So(rules[1], ShouldResemble, "\"val1\"")
			So(rules[0], ShouldResemble, "\"val2\"")
		})

		Convey("When I insert two rules in the first and last position of the array ", func() {
			err := p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, inputChain, 2, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			rules := p.rules[mangle][inputChain]
			So(rules[0], ShouldResemble, "\"val1\"")
			So(rules[1], ShouldResemble, "\"val2\"")
		})

		Convey("When I insert two rules in the first and a bad position in the array, the last one should be last ", func() {
			err := p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, inputChain, 6, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			rules := p.rules[mangle][inputChain]
			So(rules[0], ShouldResemble, "\"val1\"")
			So(rules[1], ShouldResemble, "\"val2\"")
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
			So(rules[0], ShouldResemble, "\"val1\"")
			So(rules[1], ShouldResemble, "\"val1-2\"")
			So(rules[2], ShouldResemble, "\"val2\"")
			So(rules[3], ShouldResemble, "\"val2-3\"")
			So(rules[4], ShouldResemble, "\"val3\"")
		})

		Convey("When I Insert two rules in different chains, there should be two chains", func() {
			err := p.Insert(mangle, inputChain, 1, "val1")
			So(err, ShouldBeNil)
			err = p.Insert(mangle, outputChain, 1, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 2)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(len(p.rules[mangle][outputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
			So(p.rules[mangle][outputChain][0], ShouldResemble, "\"val2\"")
		})
	})
}

func TestInsertWithQuoteFalse(t *testing.T) {
	Convey("Given a valid batch provider", t, func() {
		p := NewTestProvider([]string{mangle}, false)
		So(p, ShouldNotBeNil)

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
		p := NewTestProvider([]string{mangle}, true)
		So(p, ShouldNotBeNil)

		Convey("When I have one rule, I should be able to delete it", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
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
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
			So(p.rules[mangle][inputChain][1], ShouldResemble, "\"val2\"")
			err = p.Delete(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
		})

		Convey("When I have two rules, I should be able to delete the first one", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			err = p.Append(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
			So(p.rules[mangle][inputChain][1], ShouldResemble, "\"val2\"")
			err = p.Delete(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val2\"")
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
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
			So(p.rules[mangle][inputChain][1], ShouldResemble, "\"val2\"")
			So(p.rules[mangle][inputChain][2], ShouldResemble, "\"val3\"")
			err = p.Delete(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
			So(p.rules[mangle][inputChain][1], ShouldResemble, "\"val3\"")
		})
	})
}

func TestClearChain(t *testing.T) {
	Convey("Given a valid batch provider", t, func() {
		p := NewTestProvider([]string{mangle}, true)
		So(p, ShouldNotBeNil)

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
			So(p.rules[mangle][inputChain][0], ShouldResemble, "\"val1\"")
			err = p.ClearChain(mangle, inputChain)
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 0)
		})
	})
}

func TestDeleteChain(t *testing.T) {
	Convey("Given a valid batch provider", t, func() {
		p := NewTestProvider([]string{mangle}, true)
		So(p, ShouldNotBeNil)

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

func TestProvider(t *testing.T) { // TODO - fix this test - it calls out to system iptables
	b, err := NewGoIPTablesProviderV4([]string{})
	assert.Equal(t, b != nil, true, "go iptables should not be nil")
	assert.Equal(t, err == nil, true, "error should be nil")
	b, err = NewGoIPTablesProviderV6([]string{})
	assert.Equal(t, b != nil, true, "go iptables should not be nil")
	assert.Equal(t, err == nil, true, "error should be nil")
}

func TestQuoteRuleSpec(t *testing.T) {
	Convey("Given a valid, non-quoting batch provider", t, func() {
		p := NewTestProvider([]string{mangle}, false)
		So(p, ShouldNotBeNil)

		Convey("If I append a rule, it should not be quoted", func() {
			p.quoteRulesSpec([]string{mangle})
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldEqual, "val1")
		})
	})
	Convey("Given a valid, quoting batch provider", t, func() {
		p := NewTestProvider([]string{mangle}, true)
		So(p, ShouldNotBeNil)

		Convey("If I append a rule, it should be quoted", func() {
			p.quoteRulesSpec([]string{mangle})
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 1)
			So(p.rules[mangle][inputChain][0], ShouldEqual, "\"val1\"")
		})
	})
}

func TestListChains(t *testing.T) {
	Convey("Given a valid batch provider without an iptables implementation attached", t, func() {
		p := NewTestProvider([]string{mangle}, false)
		So(p, ShouldNotBeNil)

		Convey("if I list the mangle chain, it should be empty", func() {
			chains, err := p.ListChains(mangle)
			So(err, ShouldNotBeNil)
			So(chains, ShouldBeEmpty)
		})
		Convey("if I list the nat chain, it should be empty", func() {
			chains, err := p.ListChains(nat)
			So(err, ShouldNotBeNil)
			So(chains, ShouldBeEmpty)
		})
	})
	Convey("Given a custom batch provider with a mocked iptables implementation attached but failing", t, func() {
		p := NewCustomBatchProvider(&failingIpt{}, nil, []string{"nat", "mangle"})
		So(p, ShouldNotBeNil)

		Convey("if I list the mangle chain, it should error and should be empty", func() {
			chains, err := p.ListChains(mangle)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "not found")
			So(chains, ShouldBeEmpty)
		})
		Convey("if I list the nat chain, it should error and should be empty", func() {
			chains, err := p.ListChains(nat)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "not found")
			So(chains, ShouldBeEmpty)
		})
	})
	Convey("Given a custom batch provider with a mocked iptables implementation that returns nothing", t, func() {
		p := NewCustomBatchProvider(&emptyListIpt{}, nil, []string{"nat", "mangle"})
		So(p, ShouldNotBeNil)

		Convey("if I list the mangle chain, it should error and should be empty", func() {
			chains, err := p.ListChains(mangle)
			So(err, ShouldBeNil)
			So(chains, ShouldBeEmpty)
		})
		Convey("if I list the nat chain, it should error and should be empty", func() {
			chains, err := p.ListChains(nat)
			So(err, ShouldBeNil)
			So(chains, ShouldBeEmpty)
		})
	})
	Convey("Given a custom batch provider with a mocked iptables implementation that returns a non-empty, but clear system iptable", t, func() {
		p := NewCustomBatchProvider(&emptySystemListIpt{}, nil, []string{"nat", "mangle"})
		So(p, ShouldNotBeNil)

		Convey("if I list the mangle chain, it should not error and should be empty", func() {
			chains, err := p.ListChains(mangle)
			So(err, ShouldBeNil)
			So(chains, ShouldNotBeEmpty)
			So(len(p.rules[mangle]), ShouldEqual, 5)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 0)
		})
		Convey("if I list the nat chain, it should not error and should be empty", func() {
			chains, err := p.ListChains(nat)
			So(err, ShouldBeNil)
			So(chains, ShouldNotBeEmpty)
			So(len(p.rules[nat]), ShouldEqual, 4)
			So(len(p.rules[nat][outputChain]), ShouldEqual, 0)
		})

	})
	Convey("Given a custom batch provider with a mocked iptables implementation that returns a populated system iptable", t, func() {
		p := NewCustomBatchProvider(&validSystemListIpt{}, nil, []string{"nat", "mangle"})
		So(p, ShouldNotBeNil)

		Convey("if I list the mangle chain, it should error and should be empty", func() {
			chains, err := p.ListChains(mangle)
			So(err, ShouldBeNil)
			So(chains, ShouldNotBeEmpty)
			So(len(chains), ShouldEqual, 6)
			So(len(p.rules[mangle]), ShouldEqual, 6)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 0)
		})
		Convey("if I list the nat chain, it should error and should be empty", func() {
			chains, err := p.ListChains(nat)
			So(err, ShouldBeNil)
			So(chains, ShouldNotBeEmpty)
			So(len(chains), ShouldEqual, 4)
			So(len(p.rules[nat]), ShouldEqual, 4)
			So(len(p.rules[nat][inputChain]), ShouldEqual, 0)
		})

	})
}

func TestCreateDataBuffer(t *testing.T) {
	Convey("Given a valid batch provider without an iptables implementation attached", t, func() {
		p := NewTestProvider([]string{mangle}, false) // non-quoting
		So(p, ShouldNotBeNil)
		Convey("if I append rules to the mangle chain and create a buffer from the rules, it should be non-empty", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			err = p.Append(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			rules := p.rules[mangle][inputChain]
			So(rules[0], ShouldResemble, "val1")
			So(rules[1], ShouldResemble, "val2")
			buf, err := p.createDataBuffer()

			So(err, ShouldBeNil)
			So(buf, ShouldNotBeEmpty)
			So(len(buf.Bytes()), ShouldBeGreaterThan, 0)
		})
	})
}

func TestCommit(t *testing.T) {
	Convey("Given a valid batch provider without an iptables implementation attached", t, func() {
		p := NewTestProvider([]string{mangle}, true) // quoting
		So(p, ShouldNotBeNil)
		Convey("if I append rules to the mangle chain and commit the rules with no commitFunc, it should succeed", func() {
			err := p.Append(mangle, inputChain, "val1")
			So(err, ShouldBeNil)
			err = p.Append(mangle, inputChain, "val2")
			So(err, ShouldBeNil)
			So(len(p.rules[mangle]), ShouldEqual, 1)
			So(len(p.rules[mangle][inputChain]), ShouldEqual, 2)
			rules := p.rules[mangle][inputChain]
			So(rules[0], ShouldResemble, "\"val1\"")
			So(rules[1], ShouldResemble, "\"val2\"")
			err = p.Commit()
			So(err, ShouldBeNil)
		})
	})
}
