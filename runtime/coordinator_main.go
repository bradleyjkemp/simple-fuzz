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
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"syscall"
	"time"

	. "github.com/bradleyjkemp/simple-fuzz/coverage"
)

var (
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

	s, err := newStorage()
	if err != nil {
		fmt.Println("Failed to load data:", err)
		os.Exit(1)
	}
	f := &Fuzzer{
		badInputs:        make(map[Sig]struct{}),
		suppressedSigs:   make(map[Sig]struct{}),
		maxCover:         make([]byte, CoverSize),
		fuzzFunc:         fuzzFunc,
		mutator:          newMutator(),
		lastSync:         time.Time{},
		storage:          s,
		startTime:        time.Now(),
		lastInput:        time.Now(),
		currentCandidate: nil,
		lastExec:         time.Now(),
	}
	go f.watchForHangingInputs()

	if len(f.storage.corpus) == 0 {
		f.storage.addInput([]byte{})
	}

	//Triage the initial corpus.
	for _, a := range f.storage.corpus {
		if shutdown.Err() != nil {
			break
		}
		f.broadcastStats()
		f.triageInput(a)
	}

	for shutdown.Err() == nil {
		f.broadcastStats()
		if *flagV >= 1 {
			log.Printf("worker loop crasherQueue=%d triageQueue=%d", len(f.crasherQueue), len(f.triageQueue))
		}
		if len(f.crasherQueue) > 0 {
			n := len(f.crasherQueue) - 1
			crash := f.crasherQueue[n]
			f.crasherQueue[n] = NewCrasherArgs{}
			f.crasherQueue = f.crasherQueue[:n]
			if *flagV >= 2 {
				log.Printf("worker processes crasher [%v]%x", len(crash.Data), hash(crash.Data))
			}
			f.processCrasher(crash)
			continue
		}

		if len(f.triageQueue) > 0 {
			input := f.triageQueue[0]
			f.triageQueue = f.triageQueue[1:]
			if *flagV >= 2 {
				log.Printf("worker triages local input [%v]%x", len(input), hash(input))
			}
			f.triageInput(input)
			continue
		}

		// Plain old blind fuzzing.
		data := f.mutator.generate(f.storage, Literals)
		f.triageInput(data)
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
