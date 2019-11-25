// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"
)

// Fuzzer manages persistent fuzzer state like input corpus and crashers.
type Fuzzer struct {
	badInputs      map[Sig]struct{}
	suppressedSigs map[Sig]struct{}
	maxCover       []byte
	fuzzFunc       func([]byte) int

	mutator *Mutator

	triageQueue  [][]byte
	crasherQueue []NewCrasherArgs

	lastSync time.Time
	execs    uint64
	restarts uint64

	storage *storage

	startTime time.Time
	lastInput time.Time

	// Used to detect when inputs have caused a hang/infinite-loop
	currentCandidate []byte
	lastExec         time.Time
}

func (f *Fuzzer) broadcastStats() {
	if time.Since(f.lastSync) < syncPeriod {
		return
	}
	f.lastSync = time.Now()

	// Count all the cover entries that have a count
	var cover int
	for _, v := range f.maxCover {
		if v > 0 {
			cover++
		}
	}

	execsPerSec := float64(f.execs) * 1e9 / float64(time.Since(f.startTime))
	fmt.Printf("corpus: %v (%v ago), crashers: %v,"+
		" execs: %v (%.0f/sec), cover: %v, uptime: %v\n",
		len(f.storage.corpus), time.Since(f.lastInput).Truncate(time.Second),
		len(f.storage.crashers), f.execs, execsPerSec, cover,
		time.Since(f.startTime).Truncate(time.Second),
	)
}

type NewCrasherArgs struct {
	Data        []byte
	Error       []byte
	Suppression []byte
	Hanging     bool
}
