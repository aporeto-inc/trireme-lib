package dmesgparser

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// Dmesg struct handle for the dmesg parser
type Dmesg struct {
	chanSize          int
	lastProcessedTime float64
	sync.Mutex
}

func getEntryTime(line string) float64 {
	leftindex := strings.Index(line, "[")
	rightIndex := strings.Index(line, "]")
	val, _ := strconv.ParseFloat(strings.TrimSpace(line[leftindex+1:rightIndex]), 64)
	return val
}

// TODOD move to Dmesg -w mode later
// func (r *Dmesg) runDmesgCommandFollowMode(outputChan chan string, interval time.Duration) {
// 	cmdCtx,cancel := context.WithTimeout(ctx, interval)
// 	defer cancel()
// 	cmd := exec.CommandContext(, "dmesg", "-w", "-l", "warn")

// }

// RunDmesgCommand runs the Dmesg command to capture raw Dmesg output
func (d *Dmesg) RunDmesgCommand() ([]string, error) {

	output, err := exec.Command("dmesg").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Cannot run Dmesg cmd %s", err)
	}

	return d.ParseDmesgOutput(string(output))
}

// ParseDmesgOutput will parse dmesg output
func (d *Dmesg) ParseDmesgOutput(dmesgOutput string) ([]string, error) {
	lines := strings.Split(strings.TrimSuffix(dmesgOutput, "\n"), "\n")
	outputslice := make([]string, len(lines))
	elementsadded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !isTraceOutput(line) {
			continue
		}
		if d.lastProcessedTime < getEntryTime(line) {
			outputslice[elementsadded] = line
			elementsadded++
		}
	}
	return outputslice[:elementsadded], nil
}

func isTraceOutput(line string) bool {
	i := strings.Index(line, "]")
	if i < 0 {
		return false
	}
	substring := strings.TrimSpace(line[:strings.Index(line, "]")+1])
	return strings.HasPrefix(line, substring+" TRACE:")
}

// New return an initialized Dmesg
func New() *Dmesg {
	return &Dmesg{
		chanSize:          10000,
		lastProcessedTime: 0,
	}
}
