package urisearch

import (
	"testing"

	"go.aporeto.io/trireme-lib/policy"
	. "github.com/smartystreets/goconvey/convey"
)

func initTrieRules() []*policy.HTTPRule {

	return []*policy.HTTPRule{
		&policy.HTTPRule{
			Methods: []string{"GET", "PUT"},
			URIs: []string{
				"/users/?/name",
				"/things/?",
			},
			Scopes: []string{"policy1"},
		},
		&policy.HTTPRule{
			Methods: []string{"PATCH"},
			URIs: []string{
				"/users/?/name",
				"/things/?",
			},
			Scopes: []string{"policy2"},
		},
		&policy.HTTPRule{
			Methods: []string{"POST"},
			URIs: []string{
				"/v1/users/?/name",
				"/v1/things/?",
			},
			Public: true,
			Scopes: []string{"policy3"},
		},
		&policy.HTTPRule{
			Methods: []string{"POST"},
			URIs:    []string{"/"},
			Scopes:  []string{"policy4"},
		},
		&policy.HTTPRule{
			Methods: []string{"PATCH"},
			URIs:    []string{"/?"},
			Scopes:  []string{"policy5"},
		},
		&policy.HTTPRule{
			Methods: []string{"HEAD"},
			URIs:    []string{"/*"},
			Scopes:  []string{"policy7"},
		},
		&policy.HTTPRule{
			Methods: []string{"HEAD"},
			URIs:    []string{"/a/?/c/d"},
			Scopes:  []string{"policy8"},
		},
		&policy.HTTPRule{
			Methods: []string{"HEAD"},
			URIs:    []string{"/a/b/?/e"},
			Scopes:  []string{"policy9"},
		},
		&policy.HTTPRule{
			Methods: []string{"HEAD"},
			URIs:    []string{"/a/*/c/x"},
			Scopes:  []string{"policy10"},
		},
		&policy.HTTPRule{
			Methods: []string{"HEAD"},
			URIs:    []string{"/a/b/?/w"},
			Scopes:  []string{"policy11"},
		},
		&policy.HTTPRule{
			Methods: []string{"HEAD"},
			URIs:    []string{"/a/b/?/y/*"},
			Scopes:  []string{"policy12"},
		},
	}
}

func TestNewAPICache(t *testing.T) {
	Convey("Given a set of valid rules", t, func() {
		rules := initTrieRules()

		Convey("When I insert them in the cache, I should get a valid cache", func() {
			c := NewAPICache(rules, "id", false)
			So(c, ShouldNotBeNil)
			So(c.methodRoots, ShouldNotBeNil)
			So(len(c.methodRoots), ShouldEqual, 5)
			So(c.methodRoots, ShouldContainKey, "GET")
			So(c.methodRoots, ShouldContainKey, "POST")
			So(c.methodRoots, ShouldContainKey, "PUT")
			So(c.methodRoots, ShouldContainKey, "PATCH")
			So(c.methodRoots, ShouldContainKey, "HEAD")
			So(c.methodRoots["GET"], ShouldNotBeNil)
			So(c.methodRoots["POST"], ShouldNotBeNil)
			So(c.methodRoots["PUT"], ShouldNotBeNil)
			So(c.methodRoots["PATCH"], ShouldNotBeNil)
			So(c.methodRoots["POST"].data, ShouldNotBeNil)
			So(len(c.methodRoots["GET"].children), ShouldEqual, 2)
		})
	})
}

func TestInsert(t *testing.T) {

	Convey("When I insert a root node, it should succeed", t, func() {
		n := &node{}
		insert(n, "/", "data")
		So(n.data.(string), ShouldResemble, "data")
		So(n.leaf, ShouldBeTrue)
	})

	Convey("When I insert a one level node, it should succeed", t, func() {
		n := &node{}
		insert(n, "/a", "data")
		So(n.leaf, ShouldEqual, false)
		So(len(n.children), ShouldEqual, 1)
		So(n.children["/a"], ShouldNotBeNil)
		So(n.children["/a"].leaf, ShouldBeTrue)
		So(n.children["/a"].data.(string), ShouldResemble, "data")
	})

	Convey("When I insert two level node, it should succeed", t, func() {
		n := &node{}
		insert(n, "/a/b", "data")
		So(n.leaf, ShouldEqual, false)
		So(len(n.children), ShouldEqual, 1)
		So(n.children["/a"], ShouldNotBeNil)
		So(n.children["/a"].leaf, ShouldBeFalse)
		So(n.children["/a"].children["/b"], ShouldNotBeNil)
		So(n.children["/a"].children["/b"].leaf, ShouldBeTrue)
	})

	Convey("When I insert two level node with a * it should succeed", t, func() {
		n := &node{}
		insert(n, "/a/*", "data")
		So(n.leaf, ShouldEqual, false)
		So(len(n.children), ShouldEqual, 1)
		So(n.children["/a"], ShouldNotBeNil)
		So(n.children["/a"].leaf, ShouldBeFalse)
		So(n.children["/a"].children["/*"], ShouldNotBeNil)
		So(n.children["/a"].children["/*"].leaf, ShouldBeTrue)
	})

	Convey("When I insert a two level node, where the first part is * it should succeed", t, func() {
		n := &node{}
		insert(n, "/*/a", "data")
		So(n.leaf, ShouldEqual, false)
		So(len(n.children), ShouldEqual, 1)
		So(n.children["/*"], ShouldNotBeNil)
		So(n.children["/*"].leaf, ShouldBeFalse)
		So(n.children["/*"].children["/a"], ShouldNotBeNil)
		So(n.children["/*"].children["/a"].leaf, ShouldBeTrue)
	})

}

func TestParse(t *testing.T) {
	Convey("When I parse a root URI, I should get no suffix", t, func() {
		prefix, suffix := parse("/")
		So(prefix, ShouldEqual, "/")
		So(suffix, ShouldEqual, "")
	})

	Convey("When I parse non root URIs with one level", t, func() {
		prefix, suffix := parse("/a")
		So(prefix, ShouldEqual, "/a")
		So(suffix, ShouldEqual, "")
	})

	Convey("When I parse non root URIs with two levels, I should get the right suffix", t, func() {
		prefix, suffix := parse("/a/b")
		So(prefix, ShouldEqual, "/a")
		So(suffix, ShouldEqual, "/b")
	})

	Convey("When I parse non root URIs with three levels, I should get the right suffix", t, func() {
		prefix, suffix := parse("/a/b/c")
		So(prefix, ShouldEqual, "/a")
		So(suffix, ShouldEqual, "/b/c")
	})

	Convey("When I parse non root URIs with a *, I should get * as suffix", t, func() {
		prefix, suffix := parse("/a/*")
		So(prefix, ShouldEqual, "/a")
		So(suffix, ShouldEqual, "/*")
	})
}

func TestAPICacheFind(t *testing.T) {
	Convey("Given valid API cache", t, func() {
		c := NewAPICache(initTrieRules(), "id", false)
		Convey("When I search for correct URIs, I should get the right data", func() {

			// GET and PUT combined rule
			found, rule := c.FindRule("GET", "/users/bob/name")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy1")

			found, rule = c.FindRule("BADVERB", "/users/bob/name")
			So(found, ShouldBeFalse)
			So(rule, ShouldBeNil)

			found, rule = c.FindRule("PUT", "/users/bob/name")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy1")

			found, rule = c.FindRule("GET", "/things/something")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy1")

			found, rule = c.FindRule("GET", "/prefix/things/something")
			So(found, ShouldBeFalse)
			So(rule, ShouldBeNil)

			// PATCH rule
			found, rule = c.FindRule("PATCH", "/things/something")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy2")

			found, rule = c.FindRule("PATCH", "/users/bob/name")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy2")

			// POST rule
			found, rule = c.FindRule("POST", "/v1/users/123/name")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy3")

			found, rule = c.FindRule("POST", "/v1/things/123454656")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy3")

			found, rule = c.FindRule("POST", "/")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy4")

			// HEAD Rules
			found, rule = c.FindRule("HEAD", "/users/123/name")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)

			found, rule = c.FindRule("PATCH", "/users/123/name")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy2")

			found, rule = c.FindRule("HEAD", "/a/b/c/d")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy8")

			found, rule = c.FindRule("HEAD", "/a/x/c/d")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy8")

			found, rule = c.FindRule("HEAD", "/a/b/x/e")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy9")

			found, rule = c.FindRule("HEAD", "/a/b/x")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)

			found, rule = c.FindRule("HEAD", "/a/b/c/d/e/c/x")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy10")

			found, rule = c.FindRule("HEAD", "/a/b/c/w")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy11")

			found, rule = c.FindRule("HEAD", "/a/b/c/z")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy7")

			found, rule = c.FindRule("HEAD", "/a/b/c/d/e/f/w")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy7")

			found, rule = c.FindRule("HEAD", "/a/b/c/y/d/e/f/g/g")
			So(found, ShouldBeTrue)
			So(rule, ShouldNotBeNil)
			So(rule.Scopes, ShouldContain, "policy12")
		})

		Convey("When I search for bad URIs, I should get not found", func() {
			found, _ := c.Find("GET", "/users/123/name/targets")
			So(found, ShouldBeFalse)
			found, _ = c.Find("PUT", "/users/name")
			So(found, ShouldBeFalse)
			found, _ = c.Find("GET", "/v1/things/123")
			So(found, ShouldBeFalse)
			found, _ = c.Find("GET", "/v1/v2/v3/v54/12312312/12321312/123123")
			So(found, ShouldBeFalse)
			found, _ = c.Find("GET", "/someapi")
			So(found, ShouldBeFalse)
			found, _ = c.Find("GET", "/")
			So(found, ShouldBeFalse)
		})

		Convey("Test performacen", func() {
			for i := 0; i < 10000; i++ {
				found, _ := c.Find("GET", "/users/123/name")
				So(found, ShouldBeTrue)
			}
		})
	})
}

func TestFindAndMachScope(t *testing.T) {
	Convey("Given a valid API cache", t, func() {
		c := NewAPICache(initTrieRules(), "id", false)

		Convey("When I search for rules matching scopes, it should return true", func() {
			found := c.FindAndMatchScope("GET", "/users/bob/name", []string{"policy1"})
			So(found, ShouldBeTrue)
		})

		Convey("When I search for an invalid URI, it should return false", func() {
			found := c.FindAndMatchScope("GET", "/this/doesnot/exist", []string{"policy1"})
			So(found, ShouldBeFalse)
		})

		Convey("When I search for a valid URI and not matching scopes, it should return false", func() {
			found := c.FindAndMatchScope("GET", "/users/bob/name", []string{"policy10"})
			So(found, ShouldBeFalse)
		})

		Convey("When I search for public rule and bad scopes it should always return true", func() {
			found := c.FindAndMatchScope("POST", "/v1/things/something", []string{"policy10"})
			So(found, ShouldBeTrue)
		})

		Convey("When I search for public rule and good scopes it should always return true", func() {
			found := c.FindAndMatchScope("POST", "/v1/things/something", []string{"policy3"})
			So(found, ShouldBeTrue)
		})
	})
}
