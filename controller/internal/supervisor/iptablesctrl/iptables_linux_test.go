package iptablesctrl

import (
	"fmt"
	"strings"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	provider "go.aporeto.io/enforcerd/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// This file contains shared implementation for Linux iptables tests

func createTestInstance(ips ipsetmanager.IpsetProvider, iptv4 provider.IptablesProvider, iptv6 provider.IptablesProvider, mode constants.ModeType, ServiceMeshType policy.ServiceMesh) (*Instance, error) {

	ipv4Impl := &ipv4{ipt: iptv4}
	ipv6Impl := &ipv6{ipt: iptv6, ipv6Enabled: true}

	fq := fqconfig.NewFilterQueue(4, []string{"0.0.0.0/0",
		"::/0"})

	ipsetmanager.SetIpsetTestInstance(ips)
	ipsv4 := ipsetmanager.V4test()
	ipsv6 := ipsetmanager.V6test()

	iptInstanceV4 := createIPInstance(ipv4Impl, ipsv4, fq, mode, nil, ServiceMeshType)
	iptInstanceV6 := createIPInstance(ipv6Impl, ipsv6, fq, mode, nil, ServiceMeshType)
	icmpAllow = testICMPAllow

	return newInstanceWithProviders(iptInstanceV4, iptInstanceV6)
}

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

// ListRules lists the rules in a table/chain
func (b *baseIpt) ListRules(table, chain string) ([]string, error) { return []string{}, nil }

// Fake memory IPset that will tell us if we are deleting or installing
// bad things.
type memoryIPSet struct {
	set map[string]bool
}

func (m *memoryIPSet) Add(entry string, timeout int) error {
	m.set[entry] = false
	return nil
}

func (m *memoryIPSet) AddOption(entry string, option string, timeout int) error {
	if option == "nomatch" {
		m.set[entry] = true
		return nil
	}
	return m.Add(entry, timeout)
}

func (m *memoryIPSet) Del(entry string) error {
	if _, ok := m.set[entry]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.set, entry)
	return nil
}

func (m *memoryIPSet) Destroy() error {
	m.set = map[string]bool{}
	return nil
}

func (m *memoryIPSet) Flush() error {
	m.set = map[string]bool{}
	return nil
}

func (m *memoryIPSet) Test(entry string) (bool, error) {
	_, ok := m.set[entry]
	// TODO nomatch
	return ok, nil
}

// Fake IpSetProvider that will use memory and allow us to
// to simulate the system.
type memoryIPSetProvider struct {
	sets map[string]*memoryIPSet
}

func (m *memoryIPSetProvider) NewIpset(name string, hasht string, p *ipset.Params) (ipsetmanager.Ipset, error) {

	if m.sets == nil {
		return nil, fmt.Errorf("error")
	}

	_, ok := m.sets[name]
	if ok {
		return nil, fmt.Errorf("set exists")
	}

	newSet := &memoryIPSet{set: map[string]bool{}}
	m.sets[name] = newSet
	return newSet, nil
}

func (m *memoryIPSetProvider) GetIpset(name string) ipsetmanager.Ipset {
	return m.sets[name]
}

func (m *memoryIPSetProvider) DestroyAll(prefix string) error {

	for set := range m.sets {
		if strings.HasPrefix(set, prefix) {
			delete(m.sets, set)
		}
	}
	return nil
}

func (m *memoryIPSetProvider) ListIPSets() ([]string, error) {
	allSets := []string{}
	for set := range m.sets {
		allSets = append(allSets, set)
	}
	return allSets, nil
}
