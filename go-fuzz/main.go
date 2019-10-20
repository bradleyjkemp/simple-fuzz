// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"golang.org/x/tools/go/packages"
)

var (
	flagWorkdir       = flag.String("workdir", ".", "dir with persistent work data")
	flagTimeout       = flag.Int("timeout", 10, "test timeout, in seconds")
	flagMinimize      = flag.Duration("minimize", 1*time.Minute, "time limit for input minimization")
	flagBin           = flag.String("bin", "", "test binary built with go-fuzz-build")
	flagFunc          = flag.String("func", "", "function to fuzz")
	flagDumpCover     = flag.Bool("dumpcover", false, "dump coverage profile into workdir")
	flagDup           = flag.Bool("dup", false, "collect duplicate crashers")
	flagTestOutput    = flag.Bool("testoutput", false, "print test binary output to stdout (for debugging only)")
	flagCoverCounters = flag.Bool("covercounters", true, "use coverage hit counters")
	flagSonar         = flag.Bool("sonar", true, "use sonar hints")
	flagV             = flag.Int("v", 0, "verbosity level")

	shutdown        context.Context
	shutdownCleanup []func()
)

func main() {
	flag.Parse()
	var shutdownCancel context.CancelFunc
	shutdown, shutdownCancel = context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT)
		<-c
		shutdownCancel()
		log.Printf("shutting down...")
		time.Sleep(2 * time.Second)
		for _, f := range shutdownCleanup {
			f()
		}
		os.Exit(0)
	}()

	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(50) // most memory is in large binary blobs
	lowerProcessPrio()

	*flagWorkdir = expandHomeDir(*flagWorkdir)
	*flagBin = expandHomeDir(*flagBin)

	if *flagWorkdir == "" {
		log.Fatalf("-workdir is not set")
	}
	if *flagBin == "" {
		// Try the default. Best effort only.
		var bin string
		cfg := new(packages.Config)
		cfg.Env = append(os.Environ(), "GO111MODULE=off")
		pkgs, err := packages.Load(cfg, ".")
		if err == nil && len(pkgs) == 1 {
			bin = pkgs[0].Name + "-fuzz.zip"
			_, err := os.Stat(bin)
			if err != nil {
				bin = ""
			}
		}
		if bin == "" {
			log.Fatalf("-bin is not set")
		}
		*flagBin = bin
	}
	go coordinatorMain()
	select {}
}

// expandHomeDir expands the tilde sign and replaces it
// with current users home directory and returns it.
func expandHomeDir(path string) string {
	if len(path) > 2 && path[:2] == "~/" {
		usr, _ := user.Current()
		path = filepath.Join(usr.HomeDir, path[2:])
	}
	return path
}
