// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sync"
	"sync/atomic"
	"time"

	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-types"
)

const (
	syncPeriod = 3 * time.Second

	minScore = 1.0
	maxScore = 1000.0
	defScore = 10.0
)

// Hub contains data shared between all worker in the process (e.g. corpus).
// This reduces memory consumption for highly parallel worker.
// Hub also handles communication with the coordinator.
type Hub struct {
	id          int
	coordinator *Coordinator

	ro atomic.Value // *ROData

	maxCoverMu sync.Mutex
	maxCover   atomic.Value // []byte

	initialTriage uint32

	corpusCoverSize int
	corpusSigs      map[Sig]struct{}
	corpusStale     bool
	hubTriageQueue  []CoordinatorInput

	triageC     chan CoordinatorInput
	newInputC   chan Input
	newCrasherC chan NewCrasherArgs

	stats         Stats
	corpusOrigins [execCount]uint64
}

type ROData struct {
	corpus       []Input
	corpusCover  []byte
	badInputs    map[Sig]struct{}
	suppressions map[Sig]struct{}
	strLits      [][]byte // string literals in testee
	intLits      [][]byte // int literals in testee
	coverBlocks  map[int][]CoverBlock
}

type Stats struct {
	execs    uint64
	restarts uint64
}

// Preliminary cover update to prevent new input thundering herd.
// This function is synchronous to reduce latency.
func (hub *Coordinator) updateMaxCover(cover []byte) bool {
	oldMaxCover := hub.maxCover.Load().([]byte)
	if !compareCover(oldMaxCover, cover) {
		return false
	}
	hub.maxCoverMu.Lock()
	defer hub.maxCoverMu.Unlock()
	oldMaxCover = hub.maxCover.Load().([]byte)
	if !compareCover(oldMaxCover, cover) {
		return false
	}
	maxCover := makeCopy(oldMaxCover)
	updateMaxCover(maxCover, cover)
	hub.maxCover.Store(maxCover)
	return true
}
