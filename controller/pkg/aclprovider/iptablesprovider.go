// +build linux darwin

package provider

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/sasha-s/go-deadlock"
	"go.uber.org/zap"
)

// IptablesProvider is an abstraction of all the methods an implementation of userspace
// iptables need to provide.
type IptablesProvider interface {
	BaseIPTables
	// Commit will commit changes if it is a batch provider.
	Commit() error
	// RetrieveTable allows a caller to retrieve the final table.
	RetrieveTable() map[string]map[string][]string
}

// BaseIPTables is the base interface of iptables functions.
type BaseIPTables interface {
	// Append apends a rule to chain of table
	Append(table, chain string, rulespec ...string) error
	// Insert inserts a rule to a chain of table at the required pos
	Insert(table, chain string, pos int, rulespec ...string) error
	// Delete deletes a rule of a chain in the given table
	Delete(table, chain string, rulespec ...string) error
	// ListChains lists all the chains associated with a table
	ListChains(table string) ([]string, error)
	// ClearChain clears a chain in a table
	ClearChain(table, chain string) error
	// DeleteChain deletes a chain in the table. There should be no references to this chain
	DeleteChain(table, chain string) error
	// NewChain creates a new chain
	NewChain(table, chain string) error
}

// BatchProvider uses iptables-restore to program ACLs
type BatchProvider struct {
	ipt BaseIPTables

	//        TABLE      CHAIN    RULES
	rules       map[string]map[string][]string
	batchTables map[string]bool

	// Allowing for custom commit functions for testing
	commitFunc func(buf *bytes.Buffer) error
	deadlock.Mutex
	cmd        string
	restoreCmd string
	quote      bool
}

const (
	cmdV4        = "iptables --wait"
	cmdV6        = "ip6tables --wait"
	restoreCmdV4 = "iptables-restore"
	restoreCmdV6 = "ip6tables-restore"
)

// TestIptablesPinned returns error if the kernel doesn't support bpf pinning in iptables
func TestIptablesPinned(bpf string) error {
	cmd := exec.Command("aporeto-iptables", strings.Fields("iptables --wait -t mangle -I OUTPUT -m bpf --object-pinned "+bpf+" -j LOG")...)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	cmd = exec.Command("aporeto-iptables", strings.Fields("iptables --wait -t mangle -D OUTPUT -m bpf --object-pinned "+bpf+" -j LOG")...)
	_, err = cmd.CombinedOutput()
	if err != nil {
		zap.L().Error("Error removing rule")
	}

	return nil
}

// NewGoIPTablesProviderV4 returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProviderV4(batchTables []string) (IptablesProvider, error) {

	batchTablesMap := map[string]bool{}
	for _, t := range batchTables {
		batchTablesMap[t] = true
	}

	b := &BatchProvider{
		cmd:         cmdV4,
		rules:       map[string]map[string][]string{},
		batchTables: batchTablesMap,
		restoreCmd:  restoreCmdV4,
		quote:       true,
	}

	b.commitFunc = b.restore

	return b, nil
}

// NewGoIPTablesProviderV6 returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProviderV6(batchTables []string) (IptablesProvider, error) {

	batchTablesMap := map[string]bool{}
	for _, t := range batchTables {
		batchTablesMap[t] = true
	}

	b := &BatchProvider{
		cmd:         cmdV6,
		rules:       map[string]map[string][]string{},
		batchTables: batchTablesMap,
		restoreCmd:  restoreCmdV6,
		quote:       true,
	}

	b.commitFunc = b.restore

	return b, nil
}

// NewCustomBatchProvider is a custom batch provider wher the downstream
// iptables utility is provided by the caller. Very useful for testing
// the ACL functions with a mock.
func NewCustomBatchProvider(ipt BaseIPTables, commit func(buf *bytes.Buffer) error, batchTables []string) *BatchProvider {

	batchTablesMap := map[string]bool{}

	for _, t := range batchTables {
		batchTablesMap[t] = true
	}

	return &BatchProvider{
		ipt:         ipt,
		rules:       map[string]map[string][]string{},
		batchTables: batchTablesMap,
		commitFunc:  commit,
	}
}

func createIPtablesCommand(iptablesCmd, table, chain, action string, rulespec ...string) []string {
	cmd := strings.Fields(iptablesCmd)
	cmd = append(cmd, "-t")
	cmd = append(cmd, table)
	cmd = append(cmd, action)
	cmd = append(cmd, chain)
	cmd = append(cmd, rulespec...)
	return cmd
}

// Append will append the provided rule to the local cache or call
// directly the iptables command depending on the table.
func (b *BatchProvider) Append(table, chain string, rulespec ...string) error {
	b.Lock()
	defer b.Unlock()

	if _, ok := b.batchTables[table]; !ok {
		cmd := createIPtablesCommand(b.cmd, table, chain, "-A", rulespec...)
		execCmd := exec.Command("aporeto-iptables", cmd...)
		s, err := execCmd.CombinedOutput()
		if err != nil {
			return errors.New(string(s))
		}

		return nil
	}

	if _, ok := b.rules[table]; !ok {
		b.rules[table] = map[string][]string{}
	}

	if _, ok := b.rules[table][chain]; !ok {
		b.rules[table][chain] = []string{}
	}

	b.quoteRulesSpec(rulespec)

	rule := strings.Join(rulespec, " ")
	b.rules[table][chain] = append(b.rules[table][chain], rule)
	return nil
}

// Insert will insert the rule in the corresponding position in the local
// cache or call the corresponding iptables command, depending on the table.
func (b *BatchProvider) Insert(table, chain string, pos int, rulespec ...string) error {

	b.Lock()
	defer b.Unlock()

	if _, ok := b.batchTables[table]; !ok {
		cmd := createIPtablesCommand(b.cmd, table, chain, "-I", rulespec...)
		execCmd := exec.Command("aporeto-iptables", cmd...)
		s, err := execCmd.CombinedOutput()
		if err != nil {
			return errors.New(string(s))
		}
		return nil
	}

	if _, ok := b.rules[table]; !ok {
		b.rules[table] = map[string][]string{}
	}

	if _, ok := b.rules[table][chain]; !ok {
		b.rules[table][chain] = []string{}
	}

	b.quoteRulesSpec(rulespec)

	rule := strings.Join(rulespec, " ")

	if pos == 1 {
		b.rules[table][chain] = append([]string{rule}, b.rules[table][chain]...)
	} else if pos > len(b.rules[table][chain]) {
		b.rules[table][chain] = append(b.rules[table][chain], rule)
	} else {
		b.rules[table][chain] = append(b.rules[table][chain], "newvalue")
		copy(b.rules[table][chain][pos-1:], b.rules[table][chain][pos-2:])
		b.rules[table][chain][pos-1] = rule
	}

	return nil
}

// Delete will delete the rule from the local cache or the system.
func (b *BatchProvider) Delete(table, chain string, rulespec ...string) error {
	b.Lock()
	defer b.Unlock()

	if _, ok := b.batchTables[table]; !ok {
		cmd := createIPtablesCommand(b.cmd, table, chain, "-D", rulespec...)
		execCmd := exec.Command("aporeto-iptables", cmd...)
		s, err := execCmd.CombinedOutput()
		if err != nil {
			return errors.New(string(s))
		}
		return nil
	}

	if _, ok := b.rules[table]; !ok {
		return nil
	}

	if _, ok := b.rules[table][chain]; !ok {
		return nil
	}

	b.quoteRulesSpec(rulespec)

	rule := strings.Join(rulespec, " ")
	for index, r := range b.rules[table][chain] {
		if rule == r {
			switch index {
			case 0:
				if len(b.rules[table][chain]) == 1 {
					b.rules[table][chain] = []string{}
				} else {
					b.rules[table][chain] = b.rules[table][chain][1:]
				}
			case len(b.rules[table][chain]) - 1:
				b.rules[table][chain] = b.rules[table][chain][:index]
			default:
				b.rules[table][chain] = append(b.rules[table][chain][:index], b.rules[table][chain][index+1:]...)
			}
			break
		}
	}

	return nil
}

// ListChains returns a slice containing the name of each chain in the specified table.
func listChains(iptablesCmd, table string) ([]string, error) {
	cmd := strings.Fields(iptablesCmd)
	cmd = append(cmd, []string{"-t", table, "-S"}...)

	execCmd := exec.Command("aporeto-iptables", cmd...)
	out, err := execCmd.CombinedOutput()
	if err != nil {
		return nil, errors.New(string(out))
	}

	result := strings.Split(string(out), "\n")

	// Iterate over rules to find all default (-P) and user-specified (-N) chains.
	// Chains definition always come before rules.
	// Format is the following:
	// -P OUTPUT ACCEPT
	// -N Custom
	var chains []string
	for _, val := range result {
		if strings.HasPrefix(val, "-P") || strings.HasPrefix(val, "-N") {
			chains = append(chains, strings.Fields(val)[1])
		} else {
			break
		}
	}
	return chains, nil
}

// ListChains will provide a list of the current chains.
func (b *BatchProvider) ListChains(table string) ([]string, error) {
	b.Lock()
	defer b.Unlock()

	chains, err := listChains(b.cmd, table)
	if err != nil {
		return []string{}, err
	}

	if _, ok := b.batchTables[table]; !ok || b.rules[table] == nil {
		return chains, nil
	}

	for _, chain := range chains {
		if _, ok := b.rules[table][chain]; !ok {
			b.rules[table][chain] = []string{}
		}
	}

	allChains := make([]string, len(b.rules[table]))
	i := 0
	for chain := range b.rules[table] {
		allChains[i] = chain
		i++
	}

	return allChains, nil
}

// ClearChain will clear the chains.
func (b *BatchProvider) ClearChain(table, chain string) error {

	b.Lock()
	defer b.Unlock()

	if _, ok := b.batchTables[table]; !ok {
		cmd := strings.Fields(b.cmd)
		cmd = append(cmd, []string{"-t", table, "-F", chain}...)
		execCmd := exec.Command("aporeto-iptables", cmd...)
		s, err := execCmd.CombinedOutput()
		if err != nil {
			return errors.New(string(s))
		}
		return nil
	}

	if _, ok := b.rules[table]; !ok {
		return nil
	}
	if _, ok := b.rules[table][chain]; !ok {
		return nil
	}

	b.rules[table][chain] = []string{}
	return nil
}

// DeleteChain will delete the chains.
func (b *BatchProvider) DeleteChain(table, chain string) error {
	b.Lock()
	defer b.Unlock()

	if _, ok := b.batchTables[table]; !ok {
		cmd := strings.Fields(b.cmd)
		cmd = append(cmd, []string{"-t", table, "-X", chain}...)
		execCmd := exec.Command("aporeto-iptables", cmd...)
		s, err := execCmd.CombinedOutput()
		if err != nil {
			return errors.New(string(s))
		}
		return nil
	}

	if _, ok := b.rules[table]; !ok {
		return nil
	}

	delete(b.rules[table], chain)
	return nil
}

// NewChain creates a new chain.
func (b *BatchProvider) NewChain(table, chain string) error {
	b.Lock()
	defer b.Unlock()

	if _, ok := b.batchTables[table]; !ok {
		cmd := strings.Fields(b.cmd)
		cmd = append(cmd, []string{"-t", table, "-N", chain}...)
		execCmd := exec.Command("aporeto-iptables", cmd...)
		s, err := execCmd.CombinedOutput()
		if err != nil {
			return errors.New(string(s))
		}
		return nil
	}

	if _, ok := b.rules[table]; !ok {
		b.rules[table] = map[string][]string{}
	}

	b.rules[table][chain] = []string{}
	return nil
}

// Commit commits the rules to the system
func (b *BatchProvider) Commit() error {
	b.Lock()
	defer b.Unlock()

	// We don't commit if we don't have any tables. This is old
	// kernel compatibility mode.
	if len(b.batchTables) == 0 {
		return nil
	}

	buf, err := b.createDataBuffer()
	if err != nil {
		return fmt.Errorf("Failed to crete buffer %s", err)
	}

	return b.commitFunc(buf)
}

// RetrieveTable allows a caller to retrieve the final table. Mostly
// needed for debuging and unit tests.
func (b *BatchProvider) RetrieveTable() map[string]map[string][]string {
	b.Lock()
	defer b.Unlock()

	return b.rules
}

func (b *BatchProvider) createDataBuffer() (*bytes.Buffer, error) {

	buf := bytes.NewBuffer([]byte{})

	for table := range b.rules {
		if _, err := fmt.Fprintf(buf, "*%s\n", table); err != nil {
			return nil, err
		}
		for chain := range b.rules[table] {
			if _, err := fmt.Fprintf(buf, ":%s - [0:0]\n", chain); err != nil {
				return nil, err
			}
		}
		for chain := range b.rules[table] {
			for _, rule := range b.rules[table][chain] {
				if _, err := fmt.Fprintf(buf, "-A %s %s\n", chain, rule); err != nil {
					return nil, err
				}
			}
		}
		if _, err := fmt.Fprintf(buf, "COMMIT\n"); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// restore will save the current DB to iptables.
func (b *BatchProvider) restore(buf *bytes.Buffer) error {

	cmd := exec.Command("aporeto-iptables", b.restoreCmd, "--wait")
	cmd.Stdin = buf
	out, err := cmd.CombinedOutput()
	if err != nil {
		again, _ := b.createDataBuffer()
		zap.L().Error("Failed to execute command", zap.Error(err),
			zap.ByteString("Output", out),
			zap.String("Output", again.String()),
		)
		return fmt.Errorf("Failed to execute iptables-restore: %s", err)
	}
	return nil
}

func (b *BatchProvider) quoteRulesSpec(rulesspec []string) {

	if !b.quote {
		return
	}

	for i, rule := range rulesspec {
		rulesspec[i] = fmt.Sprintf("\"%s\"", rule)
	}
}
