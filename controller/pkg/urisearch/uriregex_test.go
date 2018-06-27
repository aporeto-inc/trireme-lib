package urisearch

import (
	"testing"

	"go.aporeto.io/trireme-lib/policy"

	. "github.com/smartystreets/goconvey/convey"
)

func initRules() []*policy.HTTPRule {

	return []*policy.HTTPRule{
		&policy.HTTPRule{
			Methods: []string{"GET", "PUT"},
			URIs: []string{
				"/users/.+/name",
				"/things/.+/",
			},
			Scopes: []string{"app=old"},
		},
		&policy.HTTPRule{
			Methods: []string{"POST"},
			URIs: []string{
				"/v1/users/.+/name",
				"/v1/things/.+/",
			},
			Scopes: []string{"app=v1"},
		},
		&policy.HTTPRule{
			Methods: []string{},
			URIs:    []string{"/empty"},
			Scopes:  []string{"app=empty"},
		},
		&policy.HTTPRule{
			Methods: []string{},
			URIs:    []string{},
			Scopes:  []string{"app=emptyuri"},
		},
	}
}

func TestRuleString(t *testing.T) {
	Convey("When I convert and HTTP rule to a string", t, func() {
		rules := initRules()
		Convey("When I convert the rules, I should get the right strings ", func() {
			c0 := ruleString("10", rules[0])
			c1 := ruleString("20", rules[1])
			c2 := ruleString("30", rules[2])

			So(c0, ShouldResemble, "(?P<10>(GET|PUT)(/users/.+/name|/things/.+/)$)")
			So(c1, ShouldResemble, "(?P<20>(POST)(/v1/users/.+/name|/v1/things/.+/)$)")
			So(c2, ShouldResemble, "(?P<30>(PUT|GET|POST|PATCH|DELETE|HEAD)(/empty)$)")
		})
	})
}

func TestNewAPIStore(t *testing.T) {
	Convey("When I create an API store with valid rules, it should succeed", t, func() {
		rules := initRules()
		db, err := NewAPIStore(rules)
		So(err, ShouldBeNil)
		So(db, ShouldNotBeNil)
	})

	Convey("When I create an API store with invalid rules, I should get an error", t, func() {
		rules := initRules()
		rules[0].URIs = []string{"(GET"}
		db, err := NewAPIStore(rules)
		So(err, ShouldNotBeNil)
		So(db, ShouldBeNil)

		db, err = NewAPIStore([]*policy.HTTPRule{})
		So(err, ShouldNotBeNil)
		So(db, ShouldBeNil)
	})

}

func TestFind(t *testing.T) {
	Convey("When I convert and HTTP rule to a string", t, func() {
		rules := initRules()
		db, err := NewAPIStore(rules)
		So(err, ShouldBeNil)
		Convey("When I search for the rules, I should get the correct tags", func() {
			t0, err0 := db.Find("GET", "/users/1234/name")
			So(err0, ShouldBeNil)
			So(t0, ShouldContain, "app=old")
			t1, err1 := db.Find("POST", "/v1/users/123/name")
			So(err1, ShouldBeNil)
			So(t1, ShouldContain, "app=v1")
			t2, err2 := db.Find("PATCH", "/empty")
			So(err2, ShouldBeNil)
			So(t2, ShouldContain, "app=empty")
			t3, err3 := db.Find("PATCH", "/")
			So(err3, ShouldBeNil)
			So(t3, ShouldContain, "app=emptyuri")
		})
		Convey("When I search rules that do not match, I should get an error", func() {
			_, err0 := db.Find("GET", "/users/1234/name/")
			So(err0, ShouldNotBeNil)
			_, err1 := db.Find("POST", "/v1/users/123")
			So(err1, ShouldNotBeNil)
			_, err2 := db.Find("GET", "/things")
			So(err2, ShouldNotBeNil)
		})
	})
}
