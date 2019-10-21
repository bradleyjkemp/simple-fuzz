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
	"sync/atomic"
	"time"
)

// Coordinator manages persistent fuzzer state like input corpus and crashers.
type Coordinator struct {
	mu                sync.Mutex
	idSeq             int
	coordinatorWorker *CoordinatorWorker

	// *Worker
	id int

	// *Hub
	ro atomic.Value // *ROData

	maxCoverMu sync.Mutex
	maxCover   atomic.Value // []byte

	hubStats      Stats
	initialTriage uint32

	corpusCoverSize int
	corpusSigs      map[Sig]struct{}
	corpusStale     bool
	hubTriageQueue  []CoordinatorInput

	triageC     chan CoordinatorInput
	newInputC   chan Input
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
	id       int
	procs    int
	pending  []CoordinatorInput
	lastSync time.Time
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

	c.coordinatorWorker = &CoordinatorWorker{
		id:       0,
		procs:    1,
		pending:  nil,
		lastSync: time.Time{},
	}
	newWorker(c)
	// Give the worker initial corpus.
	for _, a := range c.corpus.m {
		c.hubTriageQueue = append(c.hubTriageQueue, CoordinatorInput{a.data, a.meta, execCorpus, !a.user, true})
	}
	c.initialTriage = uint32(len(c.corpus.m))

	go coordinatorLoop(c)
}

func coordinatorLoop(c *Coordinator) {
	go c.workerLoop()

	// Local buffer helps to avoid deadlocks on chan overflows.
	var triageC chan CoordinatorInput
	var triageInput CoordinatorInput
	printStatsTicker := time.Tick(3 * time.Second)
	for {
		if len(c.hubTriageQueue) > 0 && triageC == nil {
			n := len(c.hubTriageQueue) - 1
			triageInput = c.hubTriageQueue[n]
			c.hubTriageQueue[n] = CoordinatorInput{}
			c.hubTriageQueue = c.hubTriageQueue[:n]
			triageC = c.triageC
		}

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

		case triageC <- triageInput:
			// Send new input to worker for triage.
			if len(c.hubTriageQueue) > 0 {
				n := len(c.hubTriageQueue) - 1
				triageInput = c.hubTriageQueue[n]
				c.hubTriageQueue[n] = CoordinatorInput{}
				c.hubTriageQueue = c.hubTriageQueue[:n]
			} else {
				triageC = nil
				triageInput = CoordinatorInput{}
			}

		case input := <-c.newInputC:
			// New interesting input from worker.
			ro := c.ro.Load().(*ROData)
			if !compareCover(ro.corpusCover, input.cover) {
				break
			}
			sig := hash(input.data)
			if _, ok := c.corpusSigs[sig]; ok {
				break
			}

			// Passed deduplication, taking it.
			if *flagV >= 2 {
				log.Printf("hub received new input [%v]%v mine=%v", len(input.data), hash(input.data), input.mine)
			}
			c.corpusSigs[sig] = struct{}{}
			ro1 := new(ROData)
			*ro1 = *ro
			// Assign it the default score, but mark corpus for score recalculation.
			c.corpusStale = true
			scoreSum := 0
			if len(ro1.corpus) > 0 {
				scoreSum = ro1.corpus[len(ro1.corpus)-1].runningScoreSum
			}
			input.score = defScore
			input.runningScoreSum = scoreSum + defScore
			ro1.corpus = append(ro1.corpus, input)
			c.updateMaxCover(input.cover)
			ro1.corpusCover = makeCopy(ro.corpusCover)
			c.corpusCoverSize = updateMaxCover(ro1.corpusCover, input.cover)
			c.ro.Store(ro1)
			c.corpusOrigins[input.typ]++

			if input.mine {
				if err := c.NewInput(&NewInputArgs{input.data, uint64(input.depth)}, nil); err != nil {
					log.Printf("failed to connect to coordinator: %v, killing worker", err)
					return
				}
			}

			if *flagDumpCover {
				dumpCover(filepath.Join(*flagWorkdir, "coverprofile"), ro.coverBlocks, ro.corpusCover)
			}

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
		Execs:            c.workerstats.execs,
		Cover:            uint64(c.coverFullness),
		Workers:          1,
	}

	// Print stats line.
	if c.workerstats.execs != 0 && c.workerstats.restarts != 0 {
		stats.RestartsDenom = c.workerstats.execs / c.workerstats.restarts
	}

	return stats
}

type coordinatorStats struct {
	Workers, Corpus, Crashers, Execs, Cover, RestartsDenom uint64
	LastNewInputTime, StartTime                            time.Time
	Uptime                                                 string
}

func (s coordinatorStats) String() string {
	return fmt.Sprintf("worker: %v, corpus: %v (%v ago), crashers: %v,"+
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

	w := c.coordinatorWorker
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
func (c *Coordinator) sync() {
	c.mu.Lock()
	defer c.mu.Unlock()

	w := c.coordinatorWorker
	a := c.hubSync(w.pending)
	w.pending = nil

	if c.coverFullness < a.CoverFullness {
		c.coverFullness = a.CoverFullness
	}
	w.lastSync = time.Now()
}
