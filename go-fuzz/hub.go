// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-defs"
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
	sonarSites   []SonarSite
}

type Stats struct {
	execs    uint64
	restarts uint64
}

func newHub(c *Coordinator, metadata MetaData) {
	c.corpusSigs = make(map[Sig]struct{})

	coverBlocks := make(map[int][]CoverBlock)
	for _, b := range metadata.Blocks {
		coverBlocks[b.ID] = append(coverBlocks[b.ID], b)
	}
	sonarSites := make([]SonarSite, len(metadata.Sonar))
	for i, b := range metadata.Sonar {
		if i != b.ID {
			log.Fatalf("corrupted sonar metadata")
		}
		sonarSites[i].id = b.ID
		sonarSites[i].loc = fmt.Sprintf("%v:%v.%v,%v.%v", b.File, b.StartLine, b.StartCol, b.EndLine, b.EndCol)
	}
	c.maxCover.Store(make([]byte, CoverSize))

	ro := &ROData{
		corpusCover:  make([]byte, CoverSize),
		badInputs:    make(map[Sig]struct{}),
		suppressions: make(map[Sig]struct{}),
		coverBlocks:  coverBlocks,
		sonarSites:   sonarSites,
	}
	// Prepare list of string and integer literals.
	for _, lit := range metadata.Literals {
		if lit.IsStr {
			ro.strLits = append(ro.strLits, []byte(lit.Val))
		} else {
			ro.intLits = append(ro.intLits, []byte(lit.Val))
		}
	}
	c.ro.Store(ro)
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

func (hub *Coordinator) updateScores() {
	ro := hub.ro.Load().(*ROData)
	ro1 := new(ROData)
	*ro1 = *ro
	corpus := make([]Input, len(ro.corpus))
	copy(corpus, ro.corpus)
	ro1.corpus = corpus

	var sumExecTime, sumCoverSize uint64
	for _, inp := range corpus {
		sumExecTime += inp.execTime
		sumCoverSize += uint64(inp.coverSize)
	}
	n := uint64(len(corpus))
	avgExecTime := sumExecTime / n
	avgCoverSize := sumCoverSize / n

	// Phase 1: calculate score for each input independently.
	for i, inp := range corpus {
		score := defScore

		// Execution time multiplier 0.1-3x.
		// Fuzzing faster inputs increases efficiency.
		execTime := float64(inp.execTime) / float64(avgExecTime)
		if execTime > 10 {
			score /= 10
		} else if execTime > 4 {
			score /= 4
		} else if execTime > 2 {
			score /= 2
		} else if execTime < 0.25 {
			score *= 3
		} else if execTime < 0.33 {
			score *= 2
		} else if execTime < 0.5 {
			score *= 1.5
		}

		// Coverage size multiplier 0.25-3x.
		// Inputs with larger coverage are more interesting.
		coverSize := float64(inp.coverSize) / float64(avgCoverSize)
		if coverSize > 3 {
			score *= 3
		} else if coverSize > 2 {
			score *= 2
		} else if coverSize > 1.5 {
			score *= 1.5
		} else if coverSize < 0.3 {
			score /= 4
		} else if coverSize < 0.5 {
			score /= 2
		} else if coverSize < 0.75 {
			score /= 1.5
		}

		// Input depth multiplier 1-5x.
		// Deeper inputs have higher chances of digging deeper into code.
		if inp.depth < 10 {
			// no boost for you
		} else if inp.depth < 20 {
			score *= 2
		} else if inp.depth < 40 {
			score *= 3
		} else if inp.depth < 80 {
			score *= 4
		} else {
			score *= 5
		}

		// User boost (Fuzz function return value) multiplier 1-2x.
		// We don't know what it is, but user said so.
		if inp.res > 0 {
			// Assuming this is a correct input (e.g. deserialized successfully).
			score *= 2
		}

		if score < minScore {
			score = minScore
		} else if score > maxScore {
			score = maxScore
		}
		corpus[i].score = int(score)
	}

	// Phase 2: Choose a minimal set of (favored) inputs that give full coverage.
	// Non-favored inputs receive minimal score.
	type Candidate struct {
		index  int
		score  int
		chosen bool
	}
	candidates := make([]Candidate, CoverSize)
	for idx, inp := range corpus {
		corpus[idx].favored = false
		for i, c := range inp.cover {
			if c == 0 {
				continue
			}
			c = roundUpCover(c)
			if c != ro.corpusCover[i] {
				continue
			}
			if c > ro.corpusCover[i] {
				log.Fatalf("bad")
			}
			if candidates[i].score < inp.score {
				candidates[i].index = idx
				candidates[i].score = inp.score
			}
		}
	}
	for ci, cand := range candidates {
		if cand.score == 0 {
			continue
		}
		inp := &corpus[cand.index]
		inp.favored = true
		for i := ci + 1; i < CoverSize; i++ {
			c := inp.cover[i]
			if c == 0 {
				continue
			}
			c = roundUpCover(c)
			if c != ro.corpusCover[i] {
				continue
			}
			candidates[i].score = 0
		}
	}
	scoreSum := 0
	for i, inp := range corpus {
		if !inp.favored {
			inp.score = minScore
		}
		scoreSum += inp.score
		corpus[i].runningScoreSum = scoreSum
	}

	hub.ro.Store(ro1)
}
