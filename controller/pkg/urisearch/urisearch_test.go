package urisearch

import (
	"testing"

	"github.com/aporeto-inc/trireme-lib/policy"
	. "github.com/smartystreets/goconvey/convey"
)

func initTrieRules() []*policy.HTTPRule {

	return []*policy.HTTPRule{
		&policy.HTTPRule{
			Methods: []string{"GET", "PUT"},
			URIs: []string{
				"/users/*/name",
				"/things/*",
			},
			Scopes: []string{"app=old"},
		},
		&policy.HTTPRule{
			Methods: []string{"POST"},
			URIs: []string{
				"/v1/users/*/name",
				"/v1/things/*",
			},
			Scopes: []string{"app=v1"},
		},
		&policy.HTTPRule{
			Methods: []string{"POST"},
			URIs:    []string{"/"},
			Scopes:  []string{"app=root"},
		},
		&policy.HTTPRule{
			Methods: []string{"PATCH"},
			URIs:    []string{"/*"},
			Scopes:  []string{"app=rootstart"},
		},
	}
}

func TestNewAPICache(t *testing.T) {
	Convey("Given a set of valid rules", t, func() {
		rules := initTrieRules()

		Convey("When I insert them in the cache, I should get a valid cache", func() {
			c := NewAPICache(rules, "id", false)
			So(c, ShouldNotBeNil)
			So(c.root.leaf, ShouldBeTrue)
			So(c.root.data.([]string), ShouldNotBeNil)
			So(c.root.verbs, ShouldResemble, map[string]struct{}{"POST": struct{}{}})
			So(len(c.root.data.([]string)), ShouldEqual, 1)
			So(len(c.root.children), ShouldEqual, 4)
		})
	})
}

func TestInsert(t *testing.T) {
	empty := struct{}{}

	Convey("When I insert a root node, it should succeed", t, func() {
		n := &node{}
		verbs := map[string]struct{}{
			"POST": empty,
		}
		insert(n, "/", verbs, "data")
		So(n.data.(string), ShouldResemble, "data")
		So(n.leaf, ShouldBeTrue)
		So(n.verbs, ShouldResemble, verbs)
	})

	Convey("When I insert a one level node, it should succeed", t, func() {
		n := &node{}
		verbs := map[string]struct{}{
			"POST": empty,
		}
		insert(n, "/a", verbs, "data")
		So(n.leaf, ShouldEqual, false)
		So(len(n.children), ShouldEqual, 1)
		So(n.children["/a"], ShouldNotBeNil)
		So(n.children["/a"].leaf, ShouldBeTrue)
		So(n.children["/a"].data.(string), ShouldResemble, "data")
		So(n.children["/a"].verbs, ShouldResemble, verbs)
	})

	Convey("When I insert two level node, it should succeed", t, func() {
		n := &node{}
		verbs := map[string]struct{}{
			"POST": empty,
		}
		insert(n, "/a/b", verbs, "data")
		So(n.leaf, ShouldEqual, false)
		So(len(n.children), ShouldEqual, 1)
		So(n.children["/a"], ShouldNotBeNil)
		So(n.children["/a"].leaf, ShouldBeFalse)
		So(n.children["/a"].children["/b"], ShouldNotBeNil)
		So(n.children["/a"].children["/b"].leaf, ShouldBeTrue)
	})

	Convey("When I insert two level node with a * it should succeed", t, func() {
		n := &node{}
		verbs := map[string]struct{}{
			"POST": empty,
		}
		insert(n, "/a/*", verbs, "data")
		So(n.leaf, ShouldEqual, false)
		So(len(n.children), ShouldEqual, 1)
		So(n.children["/a"], ShouldNotBeNil)
		So(n.children["/a"].leaf, ShouldBeFalse)
		So(n.children["/a"].children["/*"], ShouldNotBeNil)
		So(n.children["/a"].children["/*"].leaf, ShouldBeTrue)
	})

	Convey("When I insert a two level node, where the first part is * it should succeed", t, func() {
		n := &node{}
		verbs := map[string]struct{}{
			"POST": empty,
		}
		insert(n, "/*/a", verbs, "data")
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
			found, data := c.Find("GET", "/users/123/name")
			So(found, ShouldBeTrue)
			So(data, ShouldNotBeNil)
			found, data = c.Find("PUT", "/users/123/name")
			So(found, ShouldBeTrue)
			So(data, ShouldNotBeNil)
			found, data = c.Find("GET", "/things/123")
			So(found, ShouldBeTrue)
			So(data, ShouldNotBeNil)
			found, data = c.Find("POST", "/v1/users/123/name")
			So(found, ShouldBeTrue)
			So(data, ShouldNotBeNil)
			found, data = c.Find("POST", "/v1/things/123454656")
			So(found, ShouldBeTrue)
			So(data, ShouldNotBeNil)
			found, data = c.Find("POST", "/")
			So(found, ShouldBeTrue)
			So(data, ShouldNotBeNil)
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
