package acls

import (
	"net"
	"strconv"
	"strings"

	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

type icmpRule struct {
	baseRule           string
	listOfDisjunctives []string
	policy             *policy.FlowPolicy
}

func (rule *icmpRule) match(icmpType, icmpCode int8) (*policy.FlowPolicy, bool) {

	type evaluator func(int8) bool

	processList := func(vs []string, f func(string) evaluator) []evaluator {
		vals := make([]evaluator, len(vs))

		for i, v := range vs {
			vals[i] = f(v)
		}

		return vals
	}

	genCodes := func(val string) evaluator {

		genCode := func(v string) evaluator {

			switch splits := strings.Split(v, ":"); len(splits) {
			case 1:
				numVal, _ := strconv.Atoi(v)
				return func(input int8) bool { return input == int8(numVal) }
			default:
				min := splits[0]
				max := splits[1]

				minVal, _ := strconv.Atoi(min)
				maxVal, _ := strconv.Atoi(max)

				return func(input int8) bool { return input >= int8(minVal) && input <= int8(maxVal) }
			}
		}

		splits := strings.Split(val, ",")
		vals := processList(splits, genCode)

		return func(input int8) bool {
			result := false
			for _, v := range vals {
				result = result || v(input)
			}

			return result
		}
	}

	processSingleTypeCode := func(icmpTypeCode string) (evaluator, evaluator) {
		splits := strings.Split(icmpTypeCode, "/")

		var typeEval evaluator
		var codeEval evaluator

		typeEval = func(val int8) bool { return true }
		codeEval = func(val int8) bool { return true }

		for i, val := range splits {
			switch i {
			case 0:
			case 1:
				codeVal, _ := strconv.Atoi(val)
				typeEval = func(input int8) bool { return input == int8(codeVal) }
			case 2:
				codeEval = genCodes(val)
			}
		}

		return typeEval, codeEval
	}

	matches := func(icmpType, icmpCode int8, icmpTypeCode string) bool {
		typeMatch, codeMatch := processSingleTypeCode(icmpTypeCode)
		return typeMatch(icmpType) && codeMatch(icmpCode)
	}

	if !matches(icmpType, icmpCode, rule.baseRule) {
		return rule.policy, false
	}

	action := true

	for _, r := range rule.listOfDisjunctives {
		action = false
		if matches(icmpType, icmpCode, r) {
			return rule.policy, true
		}
	}

	return rule.policy, action
}

func (a *acl) matchICMPRule(ip net.IP, icmpType int8, icmpCode int8) (*policy.FlowPolicy, *policy.FlowPolicy, error) {

	var report *policy.FlowPolicy
	var match bool

	lookup := func(val interface{}) bool {
		if val != nil {
			icmpRules := val.([]*icmpRule)
			for _, icmpRule := range icmpRules {
				report, match = icmpRule.match(icmpType, icmpCode)
				if match {
					return true
				}
			}
			return false
		}

		return false
	}

	a.icmpCache.RunFuncOnLpmIP(ip, lookup)

	if !match {
		return nil, nil, errNotFound
	}

	return report, report, nil
}
