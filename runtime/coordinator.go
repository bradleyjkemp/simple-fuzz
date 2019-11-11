// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"time"
)

// Coordinator manages persistent fuzzer state like input corpus and crashers.
type Coordinator struct {
	corpusInputs   []Input
	badInputs      map[Sig]struct{}
	suppressedSigs map[Sig]struct{}
	lits           [][]byte // string/int literals in testee
	maxCover       []byte
	fuzzFunc       func([]byte) int

	corpusSigs map[Sig]struct{}

	mutator *Mutator

	triageQueue  []Input
	crasherQueue []NewCrasherArgs

	lastSync time.Time
	execs    uint64
	restarts uint64

	corpus       *PersistentSet
	suppressions *PersistentSet
	crashers     *PersistentSet

	startTime     time.Time
	lastInput     time.Time
	coverFullness int
}

func (c *Coordinator) broadcastStats() {
	if time.Since(c.lastSync) < syncPeriod {
		return
	}
	c.lastSync = time.Now()
	corpus := uint64(len(c.corpus.m))
	crashers := uint64(len(c.crashers.m))
	uptime := time.Since(c.startTime).Truncate(time.Second)
	startTime := c.startTime
	lastNewInputTime := c.lastInput
	cover := uint64(c.coverFullness)

	var restartsDenom uint64
	if c.execs != 0 && c.restarts != 0 {
		restartsDenom = c.execs / c.restarts
	}

	execsPerSec := float64(c.execs) * 1e9 / float64(time.Since(startTime))
	// log to stdout
	fmt.Printf("corpus: %v (%v ago), crashers: %v,"+
		" restarts: 1/%v, execs: %v (%.0f/sec), cover: %v, uptime: %v\n",
		corpus, time.Since(lastNewInputTime).Truncate(time.Second),
		crashers, restartsDenom, c.execs, execsPerSec, cover,
		uptime,
	)
}

type NewCrasherArgs struct {
	Data        []byte
	Error       []byte
	Suppression []byte
	Hanging     bool
}

// NewCrasher saves new crasher input on coordinator.
func (c *Coordinator) NewCrasher(a NewCrasherArgs) {
	if !*flagDup && !c.suppressions.add(Artifact{a.Suppression, false}) {
		return // Already have this.
	}
	if !c.crashers.add(Artifact{a.Data, false}) {
		return // Already have this.
	}

	// Prepare quoted version of input to simplify creation of standalone reproducers.
	var buf bytes.Buffer
	for i := 0; i < len(a.Data); i += 20 {
		e := i + 20
		if e > len(a.Data) {
			e = len(a.Data)
		}
		fmt.Fprintf(&buf, "\t%q", a.Data[i:e])
		if e != len(a.Data) {
			fmt.Fprintf(&buf, " +")
		}
		fmt.Fprintf(&buf, "\n")
	}
	c.crashers.addDescription(a.Data, buf.Bytes(), "quoted")
	c.crashers.addDescription(a.Data, a.Error, "output")
}
