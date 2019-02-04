package dmesgparser

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type hdl struct {
	chanSize          int
	lastProcessedTime float64
	sync.Mutex
}

func getEntryTime(line string) float64 {
	leftindex := strings.Index(line, "[")
	rightIndex := strings.Index(line, "]")
	val, _ := strconv.ParseFloat(line[leftindex+1:rightIndex], 64)
	return val
}

// TODOD move to dmesg -w mode later
// func (r *hdl) runDmesgCommandFollowMode(outputChan chan string, interval time.Duration) {
// 	cmdCtx,cancel := context.WithTimeout(ctx, interval)
// 	defer cancel()
// 	cmd := exec.CommandContext(, "dmesg", "-w", "-l", "warn")

// }

// RunDmesgCommand runs the dmesg command to capture raw dmesg output
func (d *hdl) RunDmesgCommand() ([]string, error) {

	output, err := exec.Command("dmesg").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Cannot run dmesg cmd %s", err)
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

// New return an initialized hdl
func New() *hdl {
	return &hdl{
		chanSize:          10000,
		lastProcessedTime: 0,
	}
}
