package dmesgparser

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type dmesgHdl struct {
	chanSize          int
	lastProcessedTime float64
	sync.Mutex
}

func getLastEntryTime(lines []string) float64 {
	lastLine := lines[len(lines)-1]
	return getEntryTime(lastLine)
}

func getEntryTime(line string) float64 {
	leftindex := strings.Index(line, "[")
	rightIndex := strings.Index(line, "]")
	val, _ := strconv.ParseFloat(line[leftindex+1:rightIndex], 64)
	return val
}

// TODOD move to dmesg -w mode later
// func (r *dmesgHdl) runDmesgCommandFollowMode(outputChan chan string, interval time.Duration) {
// 	cmdCtx,cancel := context.WithTimeout(ctx, interval)
// 	defer cancel()
// 	cmd := exec.CommandContext(, "dmesg", "-w", "-l", "warn")

// }

func (d *dmesgHdl) RunDmesgCommand() ([]string, error) {

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
	rightIndex := strings.Index(line, "]")
	substring := line[rightIndex:]
	if strings.HasPrefix(strings.TrimSpace(substring), "TRACE:") {
		return true
	}
	return false

}

func New() *dmesgHdl {
	return &dmesgHdl{
		chanSize:          10000,
		lastProcessedTime: 0,
	}
}
