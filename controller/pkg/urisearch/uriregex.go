package urisearch

import (
	"fmt"
	"regexp"
	"strconv"

	"go.aporeto.io/trireme-lib/policy"
)

// APIStore is a database of API rules.
type APIStore struct {
	Scopes     map[string][]string
	RegEx      *regexp.Regexp
	RegExNames []string
}

// NewAPIStore creates a database of API rules based on the provided list.
func NewAPIStore(rules []*policy.HTTPRule) (*APIStore, error) {

	if len(rules) == 0 {
		return nil, fmt.Errorf("Empty rules")
	}

	scopes := make(map[string][]string)
	ruleName := "rule" + strconv.Itoa(0)
	regexString := ruleString(ruleName, rules[0])
	scopes[ruleName] = rules[0].Scopes

	for i := 1; i < len(rules); i++ {
		ruleName := "rule" + strconv.Itoa(i)
		regexString = regexString + "|" + ruleString(ruleName, rules[i])
		scopes[ruleName] = rules[i].Scopes
	}

	re, err := regexp.Compile(regexString)
	if err != nil {
		return nil, fmt.Errorf("Provided rule is not valid regular expression: %s", err)
	}

	return &APIStore{
		Scopes:     scopes,
		RegEx:      re,
		RegExNames: re.SubexpNames(),
	}, nil
}

// Find finds an API call in the database.
func (a *APIStore) Find(verb, api string) ([]string, error) {
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
			return a.Scopes[name], nil
		}
	}

	return nil, fmt.Errorf("URI Not found")
}

// ruleString converts the HTTP rule to a regular expressions string.
// It assumes that the URI is a valid Go regular expression.
func ruleString(index string, rule *policy.HTTPRule) string {
	var methods string
	if len(rule.Methods) == 0 {
		methods = "PUT|GET|POST|PATCH|DELETE|HEAD"
	} else {
		methods = rule.Methods[0]
	}
	for i := 1; i < len(rule.Methods); i++ {
		methods = methods + "|" + rule.Methods[i]
	}
	methods = fmt.Sprintf("(%s)", methods)

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

	return fmt.Sprintf("(?P<%s>%s%s$)", index, methods, uris)
}
