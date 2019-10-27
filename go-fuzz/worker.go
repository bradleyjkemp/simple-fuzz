// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-defs"
	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-types"
)

const (
	syncPeriod = 3 * time.Second
)

type ROData struct {
	corpus       []Input
	corpusCover  []byte
	badInputs    map[Sig]struct{}
	suppressions map[Sig]struct{}
	strLits      [][]byte // string literals in testee
	intLits      [][]byte // int literals in testee
	coverBlocks  map[int][]CoverBlock
}

type Input struct {
	mine      bool
	data      []byte
	cover     []byte
	coverSize int
	res       int
}

func newWorker(c *Coordinator) {
	zipr, err := zip.OpenReader(*flagBin)
	if err != nil {
		log.Fatalf("failed to open bin file: %v", err)
	}
	var coverBin string
	var metadata MetaData
	for _, zipf := range zipr.File {
		r, err := zipf.Open()
		if err != nil {
			log.Fatalf("failed to unzip file from input archive: %v", err)
		}
		if zipf.Name == "metadata" {
			if err := json.NewDecoder(r).Decode(&metadata); err != nil {
				log.Fatalf("failed to decode metadata: %v", err)
			}
		} else {
			f, err := ioutil.TempFile("", "go-fuzz")
			if err != nil {
				log.Fatalf("failed to create temp file: %v", err)
			}
			f.Close()
			os.Remove(f.Name())
			f, err = os.OpenFile(f.Name()+filepath.Base(zipf.Name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
			if err != nil {
				log.Fatalf("failed to create temp file: %v", err)
			}
			if _, err := io.Copy(f, r); err != nil {
				log.Fatalf("failed to uzip bin file: %v", err)
			}
			f.Close()
			switch zipf.Name {
			case "cover.exe":
				coverBin = f.Name()
			default:
				log.Fatalf("unknown file '%v' in input archive", f.Name())
			}
		}
		r.Close()
	}
	zipr.Close()
	if coverBin == "" || len(metadata.Blocks) == 0 || len(metadata.Funcs) == 0 {
		log.Fatalf("bad input archive: missing file")
	}

	cleanup := func() {
		os.Remove(coverBin)
	}

	// Which function should we fuzz?
	fnname := *flagFunc
	if fnname == "" {
		fnname = metadata.DefaultFunc
	}
	if fnname == "" && len(metadata.Funcs) == 1 {
		fnname = metadata.Funcs[0]
	}
	if fnname == "" {
		cleanup()
		log.Fatalf("-func flag not provided, but multiple fuzz functions available: %v", strings.Join(metadata.Funcs, ", "))
	}
	fnidx := -1
	for i, n := range metadata.Funcs {
		if n == fnname {
			fnidx = i
			break
		}
	}
	if fnidx == -1 {
		cleanup()
		log.Fatalf("function %v not found, available functions are: %v", fnname, strings.Join(metadata.Funcs, ", "))
	}
	if int(uint8(fnidx)) != fnidx {
		cleanup()
		log.Fatalf("internal consistency error, please file an issue: too many fuzz functions: %v", metadata.Funcs)
	}

	shutdownCleanup = append(shutdownCleanup, cleanup)

	c.corpusSigs = make(map[Sig]struct{})

	coverBlocks := make(map[int][]CoverBlock)
	for _, b := range metadata.Blocks {
		coverBlocks[b.ID] = append(coverBlocks[b.ID], b)
	}

	c.maxCover = make([]byte, CoverSize)

	c.ro = &ROData{
		corpusCover:  make([]byte, CoverSize),
		badInputs:    make(map[Sig]struct{}),
		suppressions: make(map[Sig]struct{}),
		coverBlocks:  coverBlocks,
	}
	// Prepare list of string and integer literals.
	for _, lit := range metadata.Literals {
		if lit.IsStr {
			c.ro.strLits = append(c.ro.strLits, []byte(lit.Val))
		} else {
			c.ro.intLits = append(c.ro.intLits, []byte(lit.Val))
		}
	}

	c.mutator = newMutator()
	c.coverBin = newTestBinary(coverBin, &c.execs, &c.restarts, uint8(fnidx))
}

func (w *Coordinator) workerLoop() {
	var lastStats time.Time
	for shutdown.Err() == nil {
		if time.Since(lastStats) > syncPeriod {
			lastStats = time.Now()
			w.broadcastStats()
		}
		if len(w.crasherQueue) > 0 {
			n := len(w.crasherQueue) - 1
			crash := w.crasherQueue[n]
			w.crasherQueue[n] = NewCrasherArgs{}
			w.crasherQueue = w.crasherQueue[:n]
			if *flagV >= 2 {
				log.Printf("worker processes crasher [%v]%v", len(crash.Data), hash(crash.Data))
			}
			w.processCrasher(crash)
			continue
		}

		if len(w.triageQueue) > 0 {
			n := len(w.triageQueue) - 1
			input := w.triageQueue[n]
			w.triageQueue[n] = CoordinatorInput{}
			w.triageQueue = w.triageQueue[:n]
			if *flagV >= 2 {
				log.Printf("worker triages local input [%v]%v minimized=%v smashed=%v", len(input.Data), hash(input.Data), input.Minimized, input.Smashed)
			}
			w.triageInput(input)
			continue
		}

		// Plain old blind fuzzing.
		data := w.mutator.generate(w.ro)
		w.testInput(data)
	}
	w.shutdown()
}

// triageInput processes every new input.
// It calculates per-input metrics like execution time, coverage mask,
// and minimizes the input to the minimal input with the same coverage.
func (w *Coordinator) triageInput(input CoordinatorInput) {
	if len(input.Data) > MaxInputSize {
		input.Data = input.Data[:MaxInputSize]
	}
	inp := Input{
		data: input.Data,
	}
	// Calculate min exec time, min coverage and max result of 3 runs.
	for i := 0; i < 3; i++ {
		w.execs++
		res, cover, output, crashed, hanged := w.coverBin.test(inp.data)
		if crashed {
			// Inputs in corpus should not crash.
			w.noteCrasher(inp.data, output, hanged)
			return
		}
		if inp.cover == nil {
			inp.cover = make([]byte, CoverSize)
			copy(inp.cover, cover)
		} else {
			for i, v := range cover {
				x := inp.cover[i]
				if v > x {
					inp.cover[i] = v
				}
			}
		}
		if inp.res < res {
			inp.res = res
		}
	}
	if !input.Minimized {
		inp.mine = true
		// When minimizing new inputs we don't pursue exactly the same coverage,
		// instead we pursue just the "novelty" in coverage.
		// Here we use corpusCover, because maxCover already includes the input coverage.
		newCover, ok := findNewCover(w.ro.corpusCover, inp.cover)
		if !ok {
			return // covered by somebody else
		}
		inp.data = w.minimizeInput(inp.data, false, func(candidate, cover, output []byte, res int, crashed, hanged bool) bool {
			if crashed {
				w.noteCrasher(candidate, output, hanged)
				return false
			}
			if inp.res != res || worseCover(newCover, cover) {
				w.noteNewInput(candidate, cover, res)
				return false
			}
			return true
		})
	}
	inp.coverSize = 0
	for _, v := range inp.cover {
		if v != 0 {
			inp.coverSize++
		}
	}

	// New interesting input from worker.
	if !compareCover(w.ro.corpusCover, inp.cover) {
		return
	}
	sig := hash(inp.data)
	if _, ok := w.corpusSigs[sig]; ok {
		return
	}

	// Passed deduplication, taking it.
	if *flagV >= 2 {
		log.Printf("hub received new input [%v]%v mine=%v", len(inp.data), hash(inp.data), inp.mine)
	}
	w.corpusSigs[sig] = struct{}{}
	w.ro.corpus = append(w.ro.corpus, inp)
	w.updateMaxCover(inp.cover)
	w.ro.corpusCover = makeCopy(w.ro.corpusCover)
	corpusCoverSize := updateMaxCover(w.ro.corpusCover, inp.cover)
	if w.coverFullness < corpusCoverSize {
		w.coverFullness = corpusCoverSize
	}

	if inp.mine {
		if err := w.NewInput(&NewInputArgs{inp.data}, nil); err != nil {
			log.Printf("failed to connect to coordinator: %v, killing worker", err)
			return
		}
	}
}

// processCrasher minimizes new crashers and sends them to the hub.
func (w *Coordinator) processCrasher(crash NewCrasherArgs) {
	// Hanging inputs can take very long time to minimize.
	if !crash.Hanging {
		crash.Data = w.minimizeInput(crash.Data, true, func(candidate, cover, output []byte, res int, crashed, hanged bool) bool {
			if !crashed {
				return false
			}
			supp := extractSuppression(output)
			if hanged || !bytes.Equal(crash.Suppression, supp) {
				w.noteCrasher(candidate, output, hanged)
				return false
			}
			crash.Error = output
			return true
		})
	}

	// New crasher from worker. Woohoo!
	if crash.Hanging || !*flagDup {
		if crash.Hanging {
			w.ro.badInputs[hash(crash.Data)] = struct{}{}
		}
		if !*flagDup {
			w.ro.suppressions[hash(crash.Suppression)] = struct{}{}
		}
	}
	w.NewCrasher(crash)
}

// minimizeInput applies series of minimizing transformations to data
// and asks pred whether the input is equivalent to the original one or not.
func (w *Coordinator) minimizeInput(data []byte, canonicalize bool, pred func(candidate, cover, output []byte, result int, crashed, hanged bool) bool) []byte {
	res := make([]byte, len(data))
	copy(res, data)
	start := time.Now()

	// First, try to cut tail.
	for n := 1024; n != 0; n /= 2 {
		for len(res) > n {
			if time.Since(start) > *flagMinimize {
				return res
			}
			candidate := res[:len(res)-n]
			w.execs++
			result, cover, output, crashed, hanged := w.coverBin.test(candidate)
			if !pred(candidate, cover, output, result, crashed, hanged) {
				break
			}
			res = candidate
		}
	}

	// Then, try to remove each individual byte.
	tmp := make([]byte, len(res))
	for i := 0; i < len(res); i++ {
		if time.Since(start) > *flagMinimize {
			return res
		}
		candidate := tmp[:len(res)-1]
		copy(candidate[:i], res[:i])
		copy(candidate[i:], res[i+1:])
		w.execs++
		result, cover, output, crashed, hanged := w.coverBin.test(candidate)
		if !pred(candidate, cover, output, result, crashed, hanged) {
			continue
		}
		res = makeCopy(candidate)
		i--
	}

	// Then, try to remove each possible subset of bytes.
	for i := 0; i < len(res)-1; i++ {
		copy(tmp, res[:i])
		for j := len(res); j > i+1; j-- {
			if time.Since(start) > *flagMinimize {
				return res
			}
			candidate := tmp[:len(res)-j+i]
			copy(candidate[i:], res[j:])
			w.execs++
			result, cover, output, crashed, hanged := w.coverBin.test(candidate)
			if !pred(candidate, cover, output, result, crashed, hanged) {
				continue
			}
			res = makeCopy(candidate)
			j = len(res)
		}
	}

	// Then, try to replace each individual byte with '0'.
	if canonicalize {
		for i := 0; i < len(res); i++ {
			if res[i] == '0' {
				continue
			}
			if time.Since(start) > *flagMinimize {
				return res
			}
			candidate := tmp[:len(res)]
			copy(candidate, res)
			candidate[i] = '0'
			w.execs++
			result, cover, output, crashed, hanged := w.coverBin.test(candidate)
			if !pred(candidate, cover, output, result, crashed, hanged) {
				continue
			}
			res = makeCopy(candidate)
		}
	}

	return res
}

func (w *Coordinator) testInput(data []byte) {
	w.testInputImpl(w.coverBin, data)
}

func (w *Coordinator) testInputImpl(bin *TestBinary, data []byte) {
	if _, ok := w.ro.badInputs[hash(data)]; ok {
		return // no, thanks
	}
	res, cover, output, crashed, hanged := bin.test(data)
	if crashed {
		w.noteCrasher(data, output, hanged)
		return
	}
	w.noteNewInput(data, cover, res)
}

func (w *Coordinator) noteNewInput(data, cover []byte, res int) {
	if res < 0 {
		// User said to not add this input to corpus.
		return
	}
	if w.updateMaxCover(cover) {
		w.triageQueue = append(w.triageQueue, CoordinatorInput{makeCopy(data), false, false})
	}
}

func (w *Coordinator) noteCrasher(data, output []byte, hanged bool) {
	supp := extractSuppression(output)
	if _, ok := w.ro.suppressions[hash(supp)]; ok {
		return
	}
	w.crasherQueue = append(w.crasherQueue, NewCrasherArgs{
		Data:        makeCopy(data),
		Error:       output,
		Suppression: supp,
		Hanging:     hanged,
	})
}

// shutdown cleanups after worker, it is not guaranteed to be called.
func (w *Coordinator) shutdown() {
	w.coverBin.close()
}

func extractSuppression(out []byte) []byte {
	var supp []byte
	seenPanic := false
	collect := false
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		line := s.Text()
		if !seenPanic && (strings.HasPrefix(line, "panic: ") ||
			strings.HasPrefix(line, "fatal error: ") ||
			strings.HasPrefix(line, "SIG") && strings.Index(line, ": ") != 0) {
			// Start of a crash message.
			seenPanic = true
			supp = append(supp, line...)
			supp = append(supp, '\n')
			if line == "SIGABRT: abort" || line == "signal: killed" {
				return supp // timeout stacks are flaky
			}
		}
		if collect && line == "runtime stack:" {
			// Skip runtime stack.
			// Unless it is a runtime bug, user stack is more descriptive.
			collect = false
		}
		if collect && len(line) > 0 && (line[0] >= 'a' && line[0] <= 'z' ||
			line[0] >= 'A' && line[0] <= 'Z') {
			// Function name line.
			idx := strings.LastIndex(line, "(")
			if idx != -1 {
				supp = append(supp, line[:idx]...)
				supp = append(supp, '\n')
			}
		}
		if collect && line == "" {
			// End of first goroutine stack.
			break
		}
		if seenPanic && !collect && line == "" {
			// Start of first goroutine stack.
			collect = true
		}
	}
	if len(supp) == 0 {
		supp = out
	}
	return supp
}

func (hub *Coordinator) updateMaxCover(cover []byte) bool {
	if !compareCover(hub.maxCover, cover) {
		return false
	}
	maxCover := makeCopy(hub.maxCover)
	updateMaxCover(maxCover, cover)
	hub.maxCover = maxCover
	return true
}
