// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"
)

// Coordinator manages persistent fuzzer state like input corpus and crashers.
type Coordinator struct {
	mu           sync.Mutex
	idSeq        int
	workers      *CoordinatorWorker
	corpus       *PersistentSet
	suppressions *PersistentSet
	crashers     *PersistentSet

	startTime     time.Time
	lastInput     time.Time
	statExecs     uint64
	statRestarts  uint64
	coverFullness int
	hub *Hub
}

// CoordinatorWorker represents coordinator's view of a worker.
type CoordinatorWorker struct {
	id       int
	procs    int
	pending  []CoordinatorInput
	lastSync time.Time
}

// coordinatorMain is entry function for coordinator.
func coordinatorMain() *Coordinator {
	m := &Coordinator{}
	m.startTime = time.Now()
	m.lastInput = time.Now()
	m.suppressions = newPersistentSet(filepath.Join(*flagWorkdir, "suppressions"))
	m.crashers = newPersistentSet(filepath.Join(*flagWorkdir, "crashers"))
	m.corpus = newPersistentSet(filepath.Join(*flagWorkdir, "corpus"))
	if len(m.corpus.m) == 0 {
		m.corpus.add(Artifact{[]byte{}, 0, false})
	}

	return m
}

func coordinatorLoop(c *Coordinator) {
	for range time.NewTicker(3 * time.Second).C {
		if shutdown.Err() != nil {
			return
		}
		c.mu.Lock()
		// Nuke dead workers. TODO: does this still make sense?
		if time.Since(c.workers.lastSync) > syncDeadline {
			log.Printf("worker %v died", c.workers.id)
			panic("uhoh")
		}
		c.mu.Unlock()

		c.sync()

		c.broadcastStats()
	}
}

func (c *Coordinator) broadcastStats() {
	stats := c.coordinatorStats()

	// log to stdout
	log.Println(stats.String())
}


func (c *Coordinator) coordinatorStats() coordinatorStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats := coordinatorStats{
		Corpus:           uint64(len(c.corpus.m)),
		Crashers:         uint64(len(c.crashers.m)),
		Uptime:           fmtDuration(time.Since(c.startTime)),
		StartTime:        c.startTime,
		LastNewInputTime: c.lastInput,
		Execs:            c.statExecs,
		Cover:            uint64(c.coverFullness),
	}

	// Print stats line.
	if c.statExecs != 0 && c.statRestarts != 0 {
		stats.RestartsDenom = c.statExecs / c.statRestarts
	}

	stats.Workers += uint64(c.workers.procs)

	return stats
}

type coordinatorStats struct {
	Workers, Corpus, Crashers, Execs, Cover, RestartsDenom uint64
	LastNewInputTime, StartTime                            time.Time
	Uptime                                                 string
}

func (s coordinatorStats) String() string {
	return fmt.Sprintf("workers: %v, corpus: %v (%v ago), crashers: %v,"+
		" restarts: 1/%v, execs: %v (%.0f/sec), cover: %v, uptime: %v",
		s.Workers, s.Corpus, fmtDuration(time.Since(s.LastNewInputTime)),
		s.Crashers, s.RestartsDenom, s.Execs, s.ExecsPerSec(), s.Cover,
		s.Uptime,
	)
}

func (s coordinatorStats) ExecsPerSec() float64 {
	return float64(s.Execs) * 1e9 / float64(time.Since(s.StartTime))
}

func fmtDuration(d time.Duration) string {
	if d.Hours() >= 1 {
		return fmt.Sprintf("%vh%vm", int(d.Hours()), int(d.Minutes())%60)
	} else if d.Minutes() >= 1 {
		return fmt.Sprintf("%vm%vs", int(d.Minutes()), int(d.Seconds())%60)
	} else {
		return fmt.Sprintf("%vs", int(d.Seconds()))
	}
}

type ConnectArgs struct {
	Procs int
}

type ConnectRes struct {
	ID     int
	Corpus []CoordinatorInput
}

// CoordinatorInput is description of input that is passed between coordinator and worker.
type CoordinatorInput struct {
	Data      []byte
	Prio      uint64
	Type      execType
	Minimized bool
	Smashed   bool
}

// Connect attaches new worker to coordinator.
func (c *Coordinator) Connect(a *ConnectArgs, r *ConnectRes) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.idSeq++
	w := &CoordinatorWorker{
		id:       c.idSeq,
		procs:    a.Procs,
		lastSync: time.Now(),
	}
	c.workers = w
	r.ID = w.id
	// Give the worker initial corpus.
	for _, a := range c.corpus.m {
		r.Corpus = append(r.Corpus, CoordinatorInput{a.data, a.meta, execCorpus, !a.user, true})
	}
	return nil
}

type NewInputArgs struct {
	ID   int
	Data []byte
	Prio uint64
}

// NewInput saves new interesting input on coordinator.
func (c *Coordinator) NewInput(a *NewInputArgs, r *int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	w := c.workers
	if w == nil {
		return errors.New("unknown worker")
	}

	art := Artifact{a.Data, a.Prio, false}
	if !c.corpus.add(art) {
		return nil
	}
	c.lastInput = time.Now()
	// Queue the input for sending to every worker.
	// TODO: does this make sense with only one worker?
	w.pending = append(w.pending, CoordinatorInput{a.Data, a.Prio, execCorpus, true, false})

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

type SyncStatus struct {
	ID            int
	Execs         uint64
	Restarts      uint64
	CoverFullness int
}

var errUnkownWorker = errors.New("unknown worker")

// Sync is a periodic sync with a worker.
// Worker sends statistics. Coordinator returns new inputs.
func (c *Coordinator) sync() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	w := c.workers
	if w == nil {
		return errUnkownWorker
	}
	a := c.hub.sync(w.pending)
	w.pending = nil

	c.statExecs += a.Execs
	c.statRestarts += a.Restarts
	if c.coverFullness < a.CoverFullness {
		c.coverFullness = a.CoverFullness
	}
	w.lastSync = time.Now()
	return nil
}
