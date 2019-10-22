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
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-defs"
	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-types"
)

type execType byte

//go:generate stringer -type execType -trimprefix exec
const (
	execBootstrap execType = iota
	execCorpus
	execMinimizeInput
	execMinimizeCrasher
	execTriageInput
	execFuzz
	execVersifier
	execSmash
	execSonar
	execSonarHint
	execTotal
	execCount
)

// Worker manages one testee.
type Worker struct {
	id int
	*Hub
	mutator *Mutator

	coverBin *TestBinary
	sonarBin *TestBinary

	triageQueue  []CoordinatorInput
	crasherQueue []NewCrasherArgs

	lastSync time.Time
	stats    Stats
	execs    [execCount]uint64
}

type Input struct {
	mine            bool
	data            []byte
	cover           []byte
	coverSize       int
	res             int
	depth           int
	typ             execType
	execTime        uint64
	favored         bool
	score           int
	runningScoreSum int
}

func newWorker(c *Coordinator) {
	zipr, err := zip.OpenReader(*flagBin)
	if err != nil {
		log.Fatalf("failed to open bin file: %v", err)
	}
	var coverBin, sonarBin string
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
			case "sonar.exe":
				sonarBin = f.Name()
			default:
				log.Fatalf("unknown file '%v' in input archive", f.Name())
			}
		}
		r.Close()
	}
	zipr.Close()
	if coverBin == "" || sonarBin == "" || len(metadata.Blocks) == 0 || len(metadata.Funcs) == 0 {
		log.Fatalf("bad input archive: missing file")
	}

	cleanup := func() {
		os.Remove(coverBin)
		os.Remove(sonarBin)
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

	newHub(c, metadata)
	c.mutator = newMutator()
	c.coverBin = newTestBinary(coverBin, c.periodicCheck, &c.workerstats, uint8(fnidx))
	c.sonarBin = newTestBinary(sonarBin, c.periodicCheck, &c.workerstats, uint8(fnidx))
}

func (w *Coordinator) workerLoop() {
	for shutdown.Err() == nil {
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

		ro := w.ro.Load().(*ROData)
		if len(ro.corpus) == 0 {
			// Some other worker triages corpus inputs.
			time.Sleep(100 * time.Millisecond)
			continue
		}

		data, depth := w.mutator.generate(ro)

		// Plain old blind fuzzing.
		w.testInput(data, depth, execFuzz)
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
		data:     input.Data,
		depth:    int(input.Prio),
		typ:      input.Type,
		execTime: 1 << 60,
	}
	// Calculate min exec time, min coverage and max result of 3 runs.
	for i := 0; i < 3; i++ {
		w.execs[execTriageInput]++
		res, ns, cover, _, output, crashed, hanged := w.coverBin.test(inp.data)
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
		if inp.execTime > ns {
			inp.execTime = ns
		}
	}
	if !input.Minimized {
		inp.mine = true
		ro := w.ro.Load().(*ROData)
		// When minimizing new inputs we don't pursue exactly the same coverage,
		// instead we pursue just the "novelty" in coverage.
		// Here we use corpusCover, because maxCover already includes the input coverage.
		newCover, ok := findNewCover(ro.corpusCover, inp.cover)
		if !ok {
			return // covered by somebody else
		}
		inp.data = w.minimizeInput(inp.data, false, func(candidate, cover, output []byte, res int, crashed, hanged bool) bool {
			if crashed {
				w.noteCrasher(candidate, output, hanged)
				return false
			}
			if inp.res != res || worseCover(newCover, cover) {
				w.noteNewInput(candidate, cover, res, inp.depth+1, execMinimizeInput)
				return false
			}
			return true
		})
	} else if !input.Smashed {
		w.smash(inp.data, inp.depth)
	}
	inp.coverSize = 0
	for _, v := range inp.cover {
		if v != 0 {
			inp.coverSize++
		}
	}

	// New interesting input from worker.
	ro := w.ro.Load().(*ROData)
	if !compareCover(ro.corpusCover, inp.cover) {
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
	ro1 := new(ROData)
	*ro1 = *ro
	// Assign it the default score, but mark corpus for score recalculation.
	w.corpusStale = true
	scoreSum := 0
	if len(ro1.corpus) > 0 {
		scoreSum = ro1.corpus[len(ro1.corpus)-1].runningScoreSum
	}
	inp.score = defScore
	inp.runningScoreSum = scoreSum + defScore
	ro1.corpus = append(ro1.corpus, inp)
	w.updateMaxCover(inp.cover)
	ro1.corpusCover = makeCopy(ro.corpusCover)
	corpusCoverSize := updateMaxCover(ro1.corpusCover, inp.cover)
	if w.coverFullness < corpusCoverSize {
		w.coverFullness = corpusCoverSize
	}
	w.ro.Store(ro1)
	w.corpusOrigins[inp.typ]++

	if inp.mine {
		if err := w.NewInput(&NewInputArgs{inp.data, uint64(inp.depth)}, nil); err != nil {
			log.Printf("failed to connect to coordinator: %v, killing worker", err)
			return
		}
	}

	if *flagDumpCover {
		dumpCover(filepath.Join(*flagWorkdir, "coverprofile"), ro.coverBlocks, ro.corpusCover)
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
		ro := w.ro.Load().(*ROData)
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
		w.ro.Store(ro1)
	}
	w.NewCrasher(crash)
}

// minimizeInput applies series of minimizing transformations to data
// and asks pred whether the input is equivalent to the original one or not.
func (w *Coordinator) minimizeInput(data []byte, canonicalize bool, pred func(candidate, cover, output []byte, result int, crashed, hanged bool) bool) []byte {
	res := make([]byte, len(data))
	copy(res, data)
	start := time.Now()
	stat := &w.execs[execMinimizeInput]
	if canonicalize {
		stat = &w.execs[execMinimizeCrasher]
	}

	// First, try to cut tail.
	for n := 1024; n != 0; n /= 2 {
		for len(res) > n {
			if time.Since(start) > *flagMinimize {
				return res
			}
			candidate := res[:len(res)-n]
			*stat++
			result, _, cover, _, output, crashed, hanged := w.coverBin.test(candidate)
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
		*stat++
		result, _, cover, _, output, crashed, hanged := w.coverBin.test(candidate)
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
			*stat++
			result, _, cover, _, output, crashed, hanged := w.coverBin.test(candidate)
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
			*stat++
			result, _, cover, _, output, crashed, hanged := w.coverBin.test(candidate)
			if !pred(candidate, cover, output, result, crashed, hanged) {
				continue
			}
			res = makeCopy(candidate)
		}
	}

	return res
}

// smash gives some minimal attention to every new input.
func (w *Coordinator) smash(data []byte, depth int) {
	ro := w.ro.Load().(*ROData)

	// Flip each bit one-by-one.
	for i := 0; i < len(data)*8; i++ {
		data[i/8] ^= 1 << uint(i%8)
		w.testInput(data, depth, execSmash)
		data[i/8] ^= 1 << uint(i%8)
	}

	// Two walking bits.
	for i := 0; i < len(data)*8-1; i++ {
		data[i/8] ^= 1 << uint(i%8)
		data[(i+1)/8] ^= 1 << uint((i+1)%8)
		w.testInput(data, depth, execSmash)
		data[i/8] ^= 1 << uint(i%8)
		data[(i+1)/8] ^= 1 << uint((i+1)%8)
	}

	// Four walking bits.
	for i := 0; i < len(data)*8-3; i++ {
		data[i/8] ^= 1 << uint(i%8)
		data[(i+1)/8] ^= 1 << uint((i+1)%8)
		data[(i+2)/8] ^= 1 << uint((i+2)%8)
		data[(i+3)/8] ^= 1 << uint((i+3)%8)
		w.testInput(data, depth, execSmash)
		data[i/8] ^= 1 << uint(i%8)
		data[(i+1)/8] ^= 1 << uint((i+1)%8)
		data[(i+2)/8] ^= 1 << uint((i+2)%8)
		data[(i+3)/8] ^= 1 << uint((i+3)%8)
	}

	// Byte flip.
	for i := 0; i < len(data); i++ {
		data[i] ^= 0xff
		w.testInput(data, depth, execSmash)
		data[i] ^= 0xff
	}

	// Two walking bytes.
	for i := 0; i < len(data)-1; i++ {
		data[i] ^= 0xff
		data[i+1] ^= 0xff
		w.testInput(data, depth, execSmash)
		data[i] ^= 0xff
		data[i+1] ^= 0xff
	}

	// Four walking bytes.
	for i := 0; i < len(data)-3; i++ {
		data[i] ^= 0xff
		data[i+1] ^= 0xff
		data[i+2] ^= 0xff
		data[i+3] ^= 0xff
		w.testInput(data, depth, execSmash)
		data[i] ^= 0xff
		data[i+1] ^= 0xff
		data[i+2] ^= 0xff
		data[i+3] ^= 0xff
	}

	// Increment/decrement every byte.
	for i := 0; i < len(data); i++ {
		for j := uint8(1); j <= 4; j++ {
			data[i] += j
			w.testInput(data, depth, execSmash)
			data[i] -= j
			data[i] -= j
			w.testInput(data, depth, execSmash)
			data[i] += j
		}
	}

	// Set bytes to interesting values.
	for i := 0; i < len(data); i++ {
		v := data[i]
		for _, x := range interesting8 {
			data[i] = uint8(x)
			w.testInput(data, depth, execSmash)
		}
		data[i] = v
	}

	// Set words to interesting values.
	for i := 0; i < len(data)-1; i++ {
		p := (*int16)(unsafe.Pointer(&data[i]))
		v := *p
		for _, x := range interesting16 {
			*p = x
			w.testInput(data, depth, execSmash)
			if x != 0 && x != -1 {
				*p = int16(bits.ReverseBytes16(uint16(x)))
				w.testInput(data, depth, execSmash)
			}
		}
		*p = v
	}

	// Set double-words to interesting values.
	for i := 0; i < len(data)-3; i++ {
		p := (*int32)(unsafe.Pointer(&data[i]))
		v := *p
		for _, x := range interesting32 {
			*p = x
			w.testInput(data, depth, execSmash)
			if x != 0 && x != -1 {
				*p = int32(bits.ReverseBytes32(uint32(x)))
				w.testInput(data, depth, execSmash)
			}
		}
		*p = v
	}

	// Trim after every byte.
	for i := 1; i < len(data); i++ {
		tmp := data[:i]
		w.testInput(tmp, depth, execSmash)
	}

	// Insert a byte after every byte.
	tmp := make([]byte, len(data)+1)
	if len(tmp) > MaxInputSize {
		tmp = tmp[:MaxInputSize]
	}
	for i := 0; i <= len(data) && i < MaxInputSize-1; i++ {
		copy(tmp, data[:i])
		copy(tmp[i+1:], data[i:])
		tmp[i] = 0
		w.testInput(tmp, depth, execSmash)
		tmp[i] = 'a'
		w.testInput(tmp, depth, execSmash)
	}

	// Do a bunch of random mutations so that this input catches up with the rest.
	for i := 0; i < 1e4; i++ {
		tmp := w.mutator.mutate(data, ro)
		w.testInput(tmp, depth+1, execFuzz)
	}
}

func (w *Coordinator) testInput(data []byte, depth int, typ execType) {
	w.testInputImpl(w.coverBin, data, depth, typ)
}

func (w *Coordinator) testInputSonar(data []byte, depth int) (sonar []byte) {
	return w.testInputImpl(w.sonarBin, data, depth, execSonar)
}

func (w *Coordinator) testInputImpl(bin *TestBinary, data []byte, depth int, typ execType) (sonar []byte) {
	ro := w.ro.Load().(*ROData)
	if len(ro.badInputs) > 0 {
		if _, ok := ro.badInputs[hash(data)]; ok {
			return nil // no, thanks
		}
	}
	w.execs[typ]++
	res, _, cover, sonar, output, crashed, hanged := bin.test(data)
	if crashed {
		w.noteCrasher(data, output, hanged)
		return nil
	}
	w.noteNewInput(data, cover, res, depth, typ)
	return sonar
}

func (w *Coordinator) noteNewInput(data, cover []byte, res, depth int, typ execType) {
	if res < 0 {
		// User said to not add this input to corpus.
		return
	}
	if w.updateMaxCover(cover) {
		w.triageQueue = append(w.triageQueue, CoordinatorInput{makeCopy(data), uint64(depth), typ, false, false})
	}
}

func (w *Coordinator) noteCrasher(data, output []byte, hanged bool) {
	ro := w.ro.Load().(*ROData)
	supp := extractSuppression(output)
	if _, ok := ro.suppressions[hash(supp)]; ok {
		return
	}
	w.crasherQueue = append(w.crasherQueue, NewCrasherArgs{
		Data:        makeCopy(data),
		Error:       output,
		Suppression: supp,
		Hanging:     hanged,
	})
}

func (w *Coordinator) periodicCheck() {
	if shutdown.Err() != nil {
		w.shutdown()
		select {}
	}
	w.execs[execTotal] = w.workerstats.execs
	if time.Since(w.lastSync) < syncPeriod {
		return
	}
	w.lastSync = time.Now()
	if *flagV >= 2 {
		log.Printf("worker triageq=%v execs=%v mininp=%v mincrash=%v triage=%v fuzz=%v versifier=%v smash=%v sonar=%v hint=%v",
			len(w.triageQueue),
			w.execs[execTotal], w.execs[execMinimizeInput], w.execs[execMinimizeCrasher],
			w.execs[execTriageInput], w.execs[execFuzz], w.execs[execVersifier], w.execs[execSmash],
			w.execs[execSonar], w.execs[execSonarHint])
	}
}

// shutdown cleanups after worker, it is not guaranteed to be called.
func (w *Coordinator) shutdown() {
	w.coverBin.close()
	w.sonarBin.close()
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
