// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gofuzzdep

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
)

var (
	flagWorkdir    = flag.String("workdir", ".", "dir with persistent work data")
	flagTimeout    = flag.Int("timeout", 10, "test timeout, in seconds")
	flagMinimize   = flag.Duration("minimize", 1*time.Minute, "time limit for input minimization")
	flagDup        = flag.Bool("dup", false, "collect duplicate crashers")
	flagTestOutput = flag.Bool("testoutput", false, "print test binary output to stdout (for debugging only)")
	flagV          = flag.Int("v", 0, "verbosity level")

	shutdown context.Context
)

func CoordinatorMain(literals []string) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	go func() {
		var cancel context.CancelFunc
		shutdown, cancel = context.WithCancel(context.Background())
		<-sigChan
		cancel()
	}()

	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(50) // most memory is in large binary blobs

	*flagWorkdir = expandHomeDir(*flagWorkdir)

	w := &Coordinator{
		startTime:      time.Now(),
		lastInput:      time.Now(),
		suppressions:   newPersistentSet(filepath.Join(*flagWorkdir, "suppressions")),
		crashers:       newPersistentSet(filepath.Join(*flagWorkdir, "crashers")),
		corpus:         newPersistentSet(filepath.Join(*flagWorkdir, "corpus")),
		badInputs:      make(map[Sig]struct{}),
		suppressedSigs: make(map[Sig]struct{}),
	}

	if len(w.corpus.m) == 0 {
		w.corpus.add(Artifact{[]byte{}, false})
	}

	// Prepare list of string and integer literals.
	for _, lit := range literals {
		w.strLits = append(w.strLits, []byte(lit))
		w.intLits = append(w.intLits, []byte(lit))
	}

	newWorker(w)
	// Give the worker initial corpus.
	for _, a := range w.corpus.m {
		w.triageQueue = append(w.triageQueue, Input{data: a.data, minimized: !a.user})
	}

	for shutdown.Err() == nil {
		if *flagV >= 1 {
			log.Printf("worker loop crasherQueue=%d triageQueue=%d", len(w.crasherQueue), len(w.triageQueue))
		}

		if time.Since(w.lastSync) > syncPeriod {
			w.broadcastStats()
			w.lastSync = time.Now()
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
			n := len(w.triageQueue) - 1
			input := w.triageQueue[n]
			w.triageQueue[n] = Input{}
			w.triageQueue = w.triageQueue[:n]
			if *flagV >= 2 {
				log.Printf("worker triages local input [%v]%x minimized=%v", len(input.data), hash(input.data), input.minimized)
			}
			w.triageInput(input)
			continue
		}

		// Plain old blind fuzzing.
		data := w.mutator.generate(w.corpusInputs, w.intLits, w.strLits)
		w.testInput(data)
	}
	w.shutdown()
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
