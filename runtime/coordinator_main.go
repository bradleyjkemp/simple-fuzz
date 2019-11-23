// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"syscall"
	"time"

	. "github.com/bradleyjkemp/simple-fuzz/coverage"
)

var (
	flagWorkdir  = flag.String("workdir", ".", "dir with persistent work data")
	flagMinimize = flag.Duration("minimize", 1*time.Minute, "time limit for input minimization")
	flagDup      = flag.Bool("dup", false, "collect duplicate crashers")
	flagV        = flag.Int("v", 0, "verbosity level")

	shutdown context.Context
)

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	go func() {
		var cancel context.CancelFunc
		shutdown, cancel = context.WithCancel(context.Background())
		//shutdown, cancel = context.WithTimeout(shutdown, 30*time.Second)
		<-sigChan
		cancel()

		// If this hasn't terminated after a delay then exit with an error
		<-time.After(time.Second)
		panic("Failed to respond to SIGINT")
	}()

	debug.SetGCPercent(50) // most memory is in large binary blobs

	*flagWorkdir = expandHomeDir(*flagWorkdir)
	s, err := newStorage(*flagWorkdir)
	if err != nil {
		fmt.Println("Failed to load data:", err)
		os.Exit(1)
	}
	w := &Fuzzer{
		startTime:      time.Now(),
		lastInput:      time.Now(),
		storage:        s,
		badInputs:      make(map[Sig]struct{}),
		suppressedSigs: make(map[Sig]struct{}),
		fuzzFunc:       fuzzFunc,
		lastExec:       time.Now(),
	}
	go w.watchForHangingInputs()

	if len(w.storage.corpus) == 0 {
		w.storage.addInput([]byte{})
	}

	// Prepare list of string and integer literals.
	for _, lit := range Literals {
		w.lits = append(w.lits, []byte(lit))
	}

	w.maxCover = make([]byte, CoverSize)

	w.mutator = newMutator()

	//Triage the initial corpus.
	for _, a := range w.storage.corpus {
		if shutdown.Err() != nil {
			break
		}
		w.broadcastStats()
		w.triageInput(Input{data: a})
	}

	for shutdown.Err() == nil {
		w.broadcastStats()
		if *flagV >= 1 {
			log.Printf("worker loop crasherQueue=%d triageQueue=%d", len(w.crasherQueue), len(w.triageQueue))
		}
		if len(w.crasherQueue) > 0 {
			n := len(w.crasherQueue) - 1
			crash := w.crasherQueue[n]
			w.crasherQueue[n] = NewCrasherArgs{}
			w.crasherQueue = w.crasherQueue[:n]
			if *flagV >= 2 {
				log.Printf("worker processes crasher [%v]%x", len(crash.Data), hash(crash.Data))
			}
			w.processCrasher(crash)
			continue
		}

		if len(w.triageQueue) > 0 {
			input := w.triageQueue[0]
			w.triageQueue = w.triageQueue[1:]
			if *flagV >= 2 {
				log.Printf("worker triages local input [%v]%x", len(input.data), hash(input.data))
			}
			w.triageInput(input)
			continue
		}

		// Plain old blind fuzzing.
		data := w.mutator.generate(w.storage.corpusInputs, w.lits)
		w.triageInput(Input{data: data})
	}
}

// Watches for inputs that are hanging and kills the process
func (f *Fuzzer) watchForHangingInputs() {
	for range time.Tick(time.Second) {
		if time.Since(f.lastExec) > 10*time.Second {
			fmt.Printf("Input causes hang: %s\n", strconv.Quote(string(f.currentCandidate)))
			b := &bytes.Buffer{}
			// TODO: this too can hang if the infinite loop isn't interruptible by the scheduler
			pprof.Lookup("goroutine").WriteTo(b, 1)
			output := fmt.Sprintf("hanger\n\n%s", b.String())
			panic(output)
		}
	}
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
