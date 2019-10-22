// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Coordinator manages persistent fuzzer state like input corpus and crashers.
type Coordinator struct {
	mu sync.Mutex

	// *Hub
	ro atomic.Value // *ROData

	maxCoverMu sync.Mutex
	maxCover   atomic.Value // []byte

	corpusSigs  map[Sig]struct{}
	corpusStale bool

	newCrasherC chan NewCrasherArgs

	corpusOrigins [execCount]uint64
	mutator       *Mutator

	coverBin *TestBinary
	sonarBin *TestBinary

	triageQueue  []CoordinatorInput
	crasherQueue []NewCrasherArgs

	lastSync    time.Time
	workerstats Stats
	execs       [execCount]uint64

	corpus       *PersistentSet
	suppressions *PersistentSet
	crashers     *PersistentSet

	startTime     time.Time
	lastInput     time.Time
	coverFullness int
}

// CoordinatorWorker represents coordinator's view of a worker.
type CoordinatorWorker struct {
	id    int
	procs int
}

// coordinatorMain is entry function for coordinator.
func coordinatorMain() {
	c := &Coordinator{}
	c.startTime = time.Now()
	c.lastInput = time.Now()
	c.suppressions = newPersistentSet(filepath.Join(*flagWorkdir, "suppressions"))
	c.crashers = newPersistentSet(filepath.Join(*flagWorkdir, "crashers"))
	c.corpus = newPersistentSet(filepath.Join(*flagWorkdir, "corpus"))
	if len(c.corpus.m) == 0 {
		c.corpus.add(Artifact{[]byte{}, 0, false})
	}

	newWorker(c)
	// Give the worker initial corpus.
	for _, a := range c.corpus.m {
		c.triageQueue = append(c.triageQueue, CoordinatorInput{a.data, a.meta, execCorpus, !a.user, true})
	}

	go coordinatorLoop(c)
}

func coordinatorLoop(c *Coordinator) {
	go c.workerLoop()

	// Local buffer helps to avoid deadlocks on chan overflows.
	printStatsTicker := time.Tick(3 * time.Second)
	for {
		select {
		case <-shutdown.Done():
			return
		default:
		}

		select {
		case <-shutdown.Done():
			return

		case <-printStatsTicker:
			c.sync()
			c.broadcastStats()

		case crash := <-c.newCrasherC:
			// New crasher from worker. Woohoo!
			if crash.Hanging || !*flagDup {
				ro := c.ro.Load().(*ROData)
				ro1 := new(ROData)
				*ro1 = *ro
				if crash.Hanging {
					ro1.badInputs = make(map[Sig]struct{})
					for k, v := range ro.badInputs {
						ro1.badInputs[k] = v
					}
					ro1.badInputs[hash(crash.Data)] = struct{}{}
				}
				if !*flagDup {
					ro1.suppressions = make(map[Sig]struct{})
					for k, v := range ro.suppressions {
						ro1.suppressions[k] = v
					}
					ro1.suppressions[hash(crash.Suppression)] = struct{}{}
				}
				c.ro.Store(ro1)
			}
			if err := c.NewCrasher(&crash, nil); err != nil {
				log.Printf("new crasher call failed: %v", err)
			}
		}
	}
}

func (c *Coordinator) broadcastStats() {
	c.mu.Lock()
	defer c.mu.Unlock()
	corpus := uint64(len(c.corpus.m))
	crashers := uint64(len(c.crashers.m))
	uptime := time.Since(c.startTime).Truncate(time.Second)
	startTime := c.startTime
	lastNewInputTime := c.lastInput
	execs := c.workerstats.execs
	cover := uint64(c.coverFullness)

	var restartsDenom uint64
	if c.workerstats.execs != 0 && c.workerstats.restarts != 0 {
		restartsDenom = c.workerstats.execs / c.workerstats.restarts
	}

	execsPerSec := float64(execs) * 1e9 / float64(time.Since(startTime))
	// log to stdout
	log.Printf("corpus: %v (%v ago), crashers: %v,"+
		" restarts: 1/%v, execs: %v (%.0f/sec), cover: %v, uptime: %v\n",
		corpus, time.Since(lastNewInputTime).Truncate(time.Second),
		crashers, restartsDenom, execs, execsPerSec, cover,
		uptime,
	)
}

// CoordinatorInput is description of input that is passed between coordinator and worker.
type CoordinatorInput struct {
	Data      []byte
	Prio      uint64
	Type      execType
	Minimized bool
	Smashed   bool
}

type NewInputArgs struct {
	Data []byte
	Prio uint64
}

// NewInput saves new interesting input on coordinator.
func (c *Coordinator) NewInput(a *NewInputArgs, r *int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	art := Artifact{a.Data, a.Prio, false}
	if !c.corpus.add(art) {
		return nil
	}
	c.lastInput = time.Now()
	c.triageQueue = append(c.triageQueue, CoordinatorInput{a.Data, a.Prio, execCorpus, true, false})

	return nil
}

type NewCrasherArgs struct {
	Data        []byte
	Error       []byte
	Suppression []byte
	Hanging     bool
}

// NewCrasher saves new crasher input on coordinator.
func (c *Coordinator) NewCrasher(a *NewCrasherArgs, r *int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !*flagDup && !c.suppressions.add(Artifact{a.Suppression, 0, false}) {
		return nil // Already have this.
	}
	if !c.crashers.add(Artifact{a.Data, 0, false}) {
		return nil // Already have this.
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

	return nil
}

// Sync is a periodic sync with a worker.
// Worker sends statistics. Coordinator returns new inputs.
func (c *Coordinator) sync() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Sync with the coordinator.
	if *flagV >= 1 {
		ro := c.ro.Load().(*ROData)
		log.Printf("hub: corpus=%v bootstrap=%v fuzz=%v minimize=%v versifier=%v smash=%v sonar=%v",
			len(ro.corpus), c.corpusOrigins[execBootstrap]+c.corpusOrigins[execCorpus],
			c.corpusOrigins[execFuzz]+c.corpusOrigins[execSonar],
			c.corpusOrigins[execMinimizeInput]+c.corpusOrigins[execMinimizeCrasher],
			c.corpusOrigins[execVersifier], c.corpusOrigins[execSmash],
			c.corpusOrigins[execSonarHint])
	}

	if c.corpusStale {
		c.updateScores()
		c.corpusStale = false
	}
}
