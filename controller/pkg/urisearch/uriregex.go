package urisearch

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/aporeto-inc/trireme-lib/policy"
)

// APIStore is a database of API rules.
type APIStore struct {
	Tags       map[string]*policy.TagStore
	RegEx      *regexp.Regexp
	RegExNames []string
}

// NewAPIStore creates a database of API rules based on the provided list.
func NewAPIStore(rules []*policy.HTTPRule) (*APIStore, error) {

	if len(rules) == 0 {
		return nil, fmt.Errorf("Empty rules")
	}

	tags := make(map[string]*policy.TagStore)
	ruleName := "rule" + strconv.Itoa(0)
	regexString := ruleString(ruleName, rules[0])
	tags[ruleName] = rules[0].Tags

	for i := 1; i < len(rules); i++ {
		ruleName := "rule" + strconv.Itoa(i)
		regexString = regexString + "|" + ruleString(ruleName, rules[i])
		tags[ruleName] = rules[i].Tags
	}

	re, err := regexp.Compile(regexString)
	if err != nil {
		return nil, fmt.Errorf("Provided rule is not valid regular expression: %s", err)
	}

	return &APIStore{
		Tags:       tags,
		RegEx:      re,
		RegExNames: re.SubexpNames(),
	}, nil
}

// Find finds an API call in the database.
func (a *APIStore) Find(verb, api string) (*policy.TagStore, error) {
	// index := a.RegEx.FindSubmatchIndex([]byte(verb + api))

	match := a.RegEx.FindStringSubmatch(verb + api)
	for i, name := range a.RegExNames {
		if i == 0 {
			continue
		}

		if i >= len(match) {
			return nil, fmt.Errorf("Failed to match")
		}

		if match[i] != "" {
			return a.Tags[name], nil
		}
	}

	return nil, fmt.Errorf("Not found")
}

// ruleString converts the HTTP rule to a regular expressions string.
// It assumes that the URI is a valid Go regular expression.
func ruleString(index string, rule *policy.HTTPRule) string {
	var verbs string
	if len(rule.Verbs) == 0 {
		verbs = "PUT|GET|POST|PATCH|DELETE"
	} else {
		verbs = rule.Verbs[0]
	}
	for i := 1; i < len(rule.Verbs); i++ {
		verbs = verbs + "|" + rule.Verbs[i]
	}
	verbs = fmt.Sprintf("(%s)", verbs)

	var uris string
	if len(rule.URIs) == 0 {
		uris = "/"
	} else {
		uris = rule.URIs[0]
	}
	for i := 1; i < len(rule.URIs); i++ {
		uris = uris + "|" + rule.URIs[i]
	}
	uris = fmt.Sprintf("(%s)", uris)

	return fmt.Sprintf("(?P<%s>%s%s$)", index, verbs, uris)
}
