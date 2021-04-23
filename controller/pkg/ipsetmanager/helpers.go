package ipsetmanager

import (
	"strings"
)

func addToIPset(set Ipset, data string) error {

	// ipset can not program this rule
	if data == IPv4DefaultIP {
		if err := addToIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		return addToIPset(set, "128.0.0.0/1")
	}

	// ipset can not program this rule
	if data == IPv6DefaultIP {
		if err := addToIPset(set, "::/1"); err != nil {
			return err
		}

		return addToIPset(set, "8000::/1")
	}

	if strings.HasPrefix(data, "!") {
		return set.AddOption(data[1:], "nomatch", 0)
	}

	return set.Add(data, 0)
}

func delFromIPset(set Ipset, data string) error {

	if data == IPv4DefaultIP {
		if err := delFromIPset(set, "0.0.0.0/1"); err != nil {
			return err
		}

		return delFromIPset(set, "128.0.0.0/1")
	}

	if data == IPv6DefaultIP {
		if err := delFromIPset(set, "::/1"); err != nil {
			return err
		}

		return delFromIPset(set, "8000::/1")
	}

	return set.Del(strings.TrimPrefix(data, "!"))
}
