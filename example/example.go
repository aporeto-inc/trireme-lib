package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aporeto-inc/trireme/example/helper"
	"github.com/pkg/profile"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: example -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {

	defer profile.Start(profile.CPUProfile).Stop()

	flag.Usage = usage

	helper.New(nil)
}
