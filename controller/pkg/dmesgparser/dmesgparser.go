package dmesgparser

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sasha-s/go-deadlock"
)

// Dmesg struct handle for the dmesg parser
type Dmesg struct {
	chanSize          int
	lastProcessedTime float64
	deadlock.Mutex
}

func getEntryTime(line string) float64 {
	leftindex := strings.Index(line, "[")
	rightIndex := strings.Index(line, "]")
	val, _ := strconv.ParseFloat(line[leftindex+1:rightIndex], 64)
	return val
}

// TODOD move to Dmesg -w mode later
// func (r *Dmesg) runDmesgCommandFollowMode(outputChan chan string, interval time.Duration) {
// 	cmdCtx,cancel := context.WithTimeout(ctx, interval)
// 	defer cancel()
// 	cmd := exec.CommandContext(, "Dmesg", "-w", "-l", "warn")

// }

// RunDmesgCommand runs the Dmesg command to capture raw Dmesg output
func (d *Dmesg) RunDmesgCommand() ([]string, error) {

	output, err := exec.Command("Dmesg").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Cannot run Dmesg cmd %s", err)
	}

	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	outputslice := make([]string, len(lines))
	elementsadded := 0

	for _, line := range lines {
		if !isTraceOutput(line) {
			continue
		}
		if d.lastProcessedTime < getEntryTime(line) {

			outputslice[elementsadded] = line
		}
	}
	return outputslice[elementsadded:], nil

}

func isTraceOutput(line string) bool {
	substring := string(line[strings.Index(line, "]")])
	return strings.HasPrefix(strings.TrimSpace(substring), "TRACE:")

}

// New return an initialized Dmesg
func New() *Dmesg {
	return &Dmesg{
		chanSize:          10000,
		lastProcessedTime: 0,
	}
}
