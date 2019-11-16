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
	lits           [][]byte // string/int literals in testee
	maxCover       []byte
	fuzzFunc       func([]byte) int

	mutator *Mutator

	triageQueue  []Input
	crasherQueue []NewCrasherArgs

	lastSync time.Time
	execs    uint64
	restarts uint64

	storage *storage

	startTime     time.Time
	lastInput     time.Time
	coverFullness int
}

func (f *Fuzzer) broadcastStats() {
	if time.Since(f.lastSync) < syncPeriod {
		return
	}
	f.lastSync = time.Now()
	corpus := uint64(len(f.storage.corpus))
	crashers := uint64(len(f.storage.crashers))
	uptime := time.Since(f.startTime).Truncate(time.Second)
	startTime := f.startTime
	lastNewInputTime := f.lastInput
	cover := uint64(f.coverFullness)

	var restartsDenom uint64
	if f.execs != 0 && f.restarts != 0 {
		restartsDenom = f.execs / f.restarts
	}

	execsPerSec := float64(f.execs) * 1e9 / float64(time.Since(startTime))
	// log to stdout
	fmt.Printf("corpus: %v (%v ago), crashers: %v,"+
		" restarts: 1/%v, execs: %v (%.0f/sec), cover: %v, uptime: %v\n",
		corpus, time.Since(lastNewInputTime).Truncate(time.Second),
		crashers, restartsDenom, f.execs, execsPerSec, cover,
		uptime,
	)
}

type NewCrasherArgs struct {
	Data        []byte
	Error       []byte
	Suppression []byte
	Hanging     bool
}
