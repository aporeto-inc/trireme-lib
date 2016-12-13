package lookup

import (
	"testing"

	"github.com/aporeto-inc/trireme/policy"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	appEqWeb = policy.KeyValueOperator{
		Key:      "app",
		Value:    []string{"web"},
		Operator: policy.Equal,
	}
	envEqDemo = policy.KeyValueOperator{
		Key:      "env",
		Value:    []string{"demo"},
		Operator: policy.Equal,
	}

	envEqDemoOrQa = policy.KeyValueOperator{
		Key:      "env",
		Value:    []string{"demo", "qa"},
		Operator: policy.Equal,
	}

	dcKeyExists = policy.KeyValueOperator{
		Key:      "dc",
		Operator: policy.KeyExists,
	}

	langNotJava = policy.KeyValueOperator{
		Key:      "lang",
		Value:    []string{"java"},
		Operator: policy.NotEqual,
	}

	langEqJava = policy.KeyValueOperator{
		Key:      "lang",
		Value:    []string{"java"},
		Operator: policy.Equal,
	}

	envNotDemoOrQA = policy.KeyValueOperator{
		Key:      "env",
		Value:    []string{"demo", "qa"},
		Operator: policy.NotEqual,
	}

	envKeyNotExists = policy.KeyValueOperator{
		Key:      "env",
		Operator: policy.KeyNotExists,
	}

	appEqWebAndenvEqDemo = policy.TagSelector{
		Clause: []policy.KeyValueOperator{appEqWeb, envEqDemo},
		Action: policy.Accept,
	}

	appEqWebAndEnvEqDemoOrQa = policy.TagSelector{
		Clause: []policy.KeyValueOperator{appEqWeb, envEqDemoOrQa},
		Action: policy.Accept,
	}

	dcTagExists = policy.TagSelector{
		Clause: []policy.KeyValueOperator{dcKeyExists},
		Action: policy.Accept,
	}

	policylangNotJava = policy.TagSelector{
		Clause: []policy.KeyValueOperator{langNotJava},
		Action: policy.Accept,
	}

	appEqWebAndenvNotDemoOrQA = policy.TagSelector{
		Clause: []policy.KeyValueOperator{appEqWeb, envNotDemoOrQA},
		Action: policy.Accept,
	}

	envKeyNotExistsAndAppEqWeb = policy.TagSelector{
		Clause: []policy.KeyValueOperator{envKeyNotExists, appEqWeb},
		Action: policy.Accept,
	}
)

// TestConstructorNewPolicyDB tests the NewPolicyDB constructor
func TestConstructorNewPolicyDB(t *testing.T) {
	Convey("Given that I instantiate a new policy DB, I should not get nil", t, func() {

		p := &PolicyDB{}

		policyDB := NewPolicyDB()

		So(policyDB, ShouldHaveSameTypeAs, p)
	})
}

// TestFuncAddPolicy tests the add policy function
func TestFuncAddPolicy(t *testing.T) {

	Convey("Given an empty policy DB", t, func() {
		policyDB := NewPolicyDB()

		Convey("When I add a single policy it should be associated with all the tags", func() {
			index := policyDB.AddPolicy(appEqWebAndenvEqDemo)

			So(policyDB.numberOfPolicies, ShouldEqual, 1)
			So(index, ShouldEqual, 1)
			for _, c := range appEqWebAndenvEqDemo.Clause {
				So(policyDB.equalMapTable[c.Key][c.Value[0]], ShouldNotEqual, nil)
				So(policyDB.equalMapTable[c.Key][c.Value[0]][0].index, ShouldEqual, index)
			}
		})

		Convey("When I add a policy with the not equal operator, it should be added to the notEqual db", func() {
			index := policyDB.AddPolicy(policylangNotJava)

			So(policyDB.numberOfPolicies, ShouldEqual, 1)
			So(index, ShouldEqual, 1)
			for _, c := range policylangNotJava.Clause {
				So(policyDB.notEqualMapTable[c.Key][c.Value[0]], ShouldNotEqual, nil)
				So(policyDB.notEqualMapTable[c.Key][c.Value[0]][0].index, ShouldEqual, index)
			}
		})

		Convey("When I add a policy with the KeyExists operator, it should be added to the KeyExists db", func() {
			index := policyDB.AddPolicy(dcTagExists)

			So(policyDB.numberOfPolicies, ShouldEqual, 1)
			So(index, ShouldEqual, 1)
			So(policyDB.starTable[dcTagExists.Clause[0].Key], ShouldNotEqual, nil)
			So(policyDB.starTable[dcTagExists.Clause[0].Key][0].index, ShouldEqual, index)
		})

	})
}

// TestFuncSearch tests the search function of the lookup
func TestFuncSearch(t *testing.T) {
	// policy1 : app=web and env=demo
	// policy2 : lang != java
	// policy3 : dc=*
	// policy4: app=web and env IN (demo, qa)
	// policy5: app=web and env NotIN (demo, qa)
	// policy6: app=web not env=*

	Convey("Given an empty policyDB", t, func() {
		policyDB := NewPolicyDB()
		Convey("Given that I add two policy rules", func() {
			index1 := policyDB.AddPolicy(appEqWebAndenvEqDemo)
			index2 := policyDB.AddPolicy(policylangNotJava)
			index3 := policyDB.AddPolicy(dcTagExists)
			index4 := policyDB.AddPolicy(appEqWebAndEnvEqDemoOrQa)
			index5 := policyDB.AddPolicy(appEqWebAndenvNotDemoOrQA)
			index6 := policyDB.AddPolicy(envKeyNotExistsAndAppEqWeb)

			So(index1, ShouldEqual, 1)
			So(index2, ShouldEqual, 2)
			So(index3, ShouldEqual, 3)
			So(index4, ShouldEqual, 4)
			So(index5, ShouldEqual, 5)
			So(index6, ShouldEqual, 6)

			Convey("Given that I search for a single matching that matches the equal rules, it should return the correct index,", func() {
				tags := policy.NewTagsMap()
				tags.Add("app", "web")
				tags.Add("env", "demo")
				index, action := policyDB.Search(tags)
				So(index, ShouldEqual, index1)
				So(action.(policy.FlowAction), ShouldEqual, policy.Accept)
			})

			Convey("Given that I search for a single matching that matches the not equal rules, it should return the right index,", func() {
				tags := policy.NewTagsMap()
				tags.Add("lang", "go")
				tags.Add("env", "demo")
				index, action := policyDB.Search(tags)
				So(index, ShouldEqual, index2)
				So(action.(policy.FlowAction), ShouldEqual, policy.Accept)
			})

			Convey("Given that I search for rules that match the KeyExists Policy, it should return the right index  ", func() {
				tags := policy.NewTagsMap()
				tags.Add("dc", "EAST")
				tags.Add("env", "demo")
				index, action := policyDB.Search(tags)
				So(index, ShouldEqual, index3)
				So(action.(policy.FlowAction), ShouldEqual, policy.Accept)
			})

			Convey("Given that I search for a single matching that matches the Or rules, it should return the right index,", func() {
				tags := policy.NewTagsMap()
				tags.Add("app", "web")
				tags.Add("env", "qa")
				index, action := policyDB.Search(tags)
				So(index, ShouldEqual, index4)
				So(action.(policy.FlowAction), ShouldEqual, policy.Accept)
			})

			Convey("Given that I search for a single matching that matches the NOT Or rlues, it should return the right index,", func() {
				tags := policy.NewTagsMap()
				tags.Add("app", "web")
				tags.Add("env", "prod")
				index, action := policyDB.Search(tags)
				So(index, ShouldEqual, index5)
				So(action.(policy.FlowAction), ShouldEqual, policy.Accept)
			})

			Convey("Given that I search for a single clause  that fails in the Not OR operator, it should fail ,", func() {
				tags := policy.NewTagsMap()
				tags.Add("app", "db")
				tags.Add("lang", "java")
				tags.Add("env", "demo")
				index, action := policyDB.Search(tags)
				So(index, ShouldEqual, -1)
				So(action, ShouldEqual, nil)
			})

			Convey("Given that I search for rules that do not match, it should return an error ", func() {
				tags := policy.NewTagsMap()
				tags.Add("tag", "none")
				index, action := policyDB.Search(tags)
				So(index, ShouldEqual, -1)
				So(action, ShouldEqual, nil)
			})

			Convey("Given that I search for a single that succeds in the Not Key  operator, it should succeed ,", func() {
				tags := policy.NewTagsMap()
				tags.Add("app", "web")
				index, action := policyDB.Search(tags)
				So(index, ShouldEqual, index6)
				So(action.(policy.FlowAction), ShouldEqual, policy.Accept)
			})

		})

	})
}

// TestFuncDumbDB is a mock test for the print function
func TestFuncDumpDB(t *testing.T) {
	Convey("Given an empty policy DB", t, func() {
		policyDB := NewPolicyDB()

		Convey("Given that I add two policy rules, I should be able to print the db ", func() {
			index1 := policyDB.AddPolicy(appEqWebAndenvEqDemo)
			index2 := policyDB.AddPolicy(policylangNotJava)
			So(index1, ShouldEqual, 1)
			So(index2, ShouldEqual, 2)

			policyDB.PrintPolicyDB()

		})
	})
}
