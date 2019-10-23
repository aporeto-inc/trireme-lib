// +build windows

package windows

import (
	"syscall"
	"unsafe"
)

var (
	kernelDll = syscall.NewLazyDLL("kernel32.dll")
	qpc       = kernelDll.NewProc("QueryPerformanceCounter")
	qpf       = kernelDll.NewProc("QueryPerformanceFrequency")
)

// returns zero on error
func QueryPerformanceCounter() int64 {
	var ctr int64
	ret, _, _ := qpc.Call(uintptr(unsafe.Pointer(&ctr)))
	if ret == 0 {
		return 0
	}
	return ctr
}

// returns zero on error
func QueryPerformanceFrequency() int64 {
	var freq int64
	ret, _, _ := qpf.Call(uintptr(unsafe.Pointer(&freq)))
	if ret == 0 {
		return 0
	}
	return freq
}

type Timer struct {
	count    int64
	start    int64
	diff     int64
	freq     int64
	quickest int64
	slowest  int64
}

// THESE ARE NOT THREADSAFE

func (t *Timer) Start() {
	t.count++
	t.start = QueryPerformanceCounter()
}

func (t *Timer) Stop() {
	stop := QueryPerformanceCounter()
	if t.start != 0 && stop != 0 {
		diff := stop - t.start
		t.diff += diff
		if diff < t.quickest || t.quickest == 0 {
			t.quickest = diff
		}
		if diff > t.slowest || t.slowest == 0 {
			t.slowest = diff
		}
	}
}

func (t *Timer) GetAverageMicroSeconds() int64 {
	if t.count == 0 {
		return 0
	}
	if t.freq == 0 {
		t.freq = QueryPerformanceFrequency()
		if t.freq == 0 {
			return 0
		}
	}
	totalMicro := (t.diff * 1000000) / t.freq
	return totalMicro / t.count
}

func (t *Timer) GetTotals() (int64, int64, int64, int64) {
	return t.diff, t.count, t.quickest, t.slowest
}
