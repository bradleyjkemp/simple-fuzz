// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gofuzzdep

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"runtime/debug"
	"strings"
	"time"

	. "github.com/bradleyjkemp/simple-fuzz/coverage"
	"github.com/maruel/panicparse/stack"
)

const (
	syncPeriod = 3 * time.Second
)

type Input struct {
	minimized bool
	data      []byte
	cover     []byte
	res       int
}

// triageInput processes every new input.
// It calculates per-input metrics like execution time, coverage mask,
// and minimizes the input to the minimal input with the same coverage.
func (w *Coordinator) triageInput(input Input) {
	if len(input.data) > MaxInputSize {
		input.data = input.data[:MaxInputSize]
	}

	res, cover, output, crashed, hanged := w.runFuzzFunc(input.data)
	if crashed {
		// Inputs in corpus should not crash.
		w.noteCrasher(input.data, output, hanged)
		return
	}

	input.res = res
	input.cover = make([]byte, CoverSize)
	copy(input.cover, cover) // cover is shared memory so needs to be copied

	if !input.minimized {
		input.minimized = true
		input.data = w.minimizeInput(input.data, false, func(candidate, cover, output []byte, res int, crashed, hanged bool) bool {
			if crashed {
				w.noteCrasher(candidate, output, hanged)
				return false
			}
			if input.res != res {
				w.noteNewInput(candidate, cover, res)
				return false
			}
			return string(input.cover) == string(cover)
		})
	}

	// New interesting input from worker.
	if !compareCover(w.maxCover, input.cover) {
		return
	}
	sig := hash(input.data)
	if _, ok := w.corpusSigs[sig]; ok {
		return
	}

	// Passed deduplication, taking it.
	if *flagV >= 2 {
		log.Printf("hub received new input [%v]%x minimized=%v", len(input.data), hash(input.data), input.minimized)
	}
	w.corpusSigs[sig] = struct{}{}
	w.corpusInputs = append(w.corpusInputs, input)
	corpusCoverSize := updateMaxCover(w.maxCover, input.cover)
	if w.coverFullness < corpusCoverSize {
		w.coverFullness = corpusCoverSize
	}

	art := Artifact{input.data, false}
	if !w.corpus.add(art) {
		// already have this
		return
	}
	w.lastInput = time.Now()
	w.triageQueue = append(w.triageQueue, input) // huh, we literally just triaged this?
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
			w.badInputs[hash(crash.Data)] = struct{}{}
		}
		if !*flagDup {
			w.suppressedSigs[hash(crash.Suppression)] = struct{}{}
		}
	}
	w.NewCrasher(crash)
}

// minimizeInput applies series of minimizing transformations to data
// and asks pred whether the input is equivalent to the original one or not.
func (w *Coordinator) minimizeInput(data []byte, canonicalize bool, pred func(candidate, cover, output []byte, result int, crashed, hanged bool) bool) []byte {
	if *flagV >= 2 {
		log.Printf("worker minimizes input [%v]%x", len(data), hash(data))
	}
	res := make([]byte, len(data))
	copy(res, data)
	start := time.Now()
	shouldStopMinimizing := func() bool {
		w.broadcastStats()
		return time.Since(start) > *flagMinimize || shutdown.Err() != nil
	}

	// First, try to cut tail.
	for n := 1024; n != 0; n /= 2 {
		for len(res) > n {
			if shouldStopMinimizing() {
				return res
			}
			candidate := res[:len(res)-n]
			result, cover, output, crashed, hanged := w.runFuzzFunc(candidate)
			if !pred(candidate, cover, output, result, crashed, hanged) {
				break
			}
			res = candidate
		}
	}

	// Then, try to remove each individual byte.
	tmp := make([]byte, len(res))
	for i := 0; i < len(res); i++ {
		if shouldStopMinimizing() {
			return res
		}
		candidate := tmp[:len(res)-1]
		copy(candidate[:i], res[:i])
		copy(candidate[i:], res[i+1:])
		result, cover, output, crashed, hanged := w.runFuzzFunc(candidate)
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
			if shouldStopMinimizing() {
				return res
			}
			candidate := tmp[:len(res)-j+i]
			copy(candidate[i:], res[j:])
			result, cover, output, crashed, hanged := w.runFuzzFunc(candidate)
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
			if shouldStopMinimizing() {
				return res
			}
			candidate := tmp[:len(res)]
			copy(candidate, res)
			candidate[i] = '0'
			result, cover, output, crashed, hanged := w.runFuzzFunc(candidate)
			if !pred(candidate, cover, output, result, crashed, hanged) {
				continue
			}
			res = makeCopy(candidate)
		}
	}

	return res
}

func (w *Coordinator) testInput(data []byte) {
	input := make([]byte, len(data))
	copy(input, data)
	if _, ok := w.badInputs[hash(data)]; ok {
		return // no, thanks
	}

	res, cover, output, crashed, hanged := w.runFuzzFunc(input)
	if crashed {
		// TODO: detect hangers again
		w.noteCrasher(data, output, hanged)
		return
	}
	w.noteNewInput(data, cover, res)
}

func (w *Coordinator) runFuzzFunc(input []byte) (result int, cover, output []byte, crashed, hanged bool) {
	w.execs++
	// TODO: detect hangers again
	defer func() {
		err := recover()
		if err != nil {
			crashed = true
			output = []byte(fmt.Sprintf("panic: %s\n\n%s", err, debug.Stack()))
		}
	}()
	for i := range CoverTab {
		CoverTab[i] = 0
	}
	result = w.fuzzFunc(input[0:len(input):len(input)])
	cover = (*CoverTab)[:]
	return
}

func (w *Coordinator) noteNewInput(data, cover []byte, res int) {
	if res < 0 {
		// User said to not add this input to corpus.
		return
	}
	if compareCover(w.maxCover, cover) {
		w.triageQueue = append(w.triageQueue, Input{data: makeCopy(data), minimized: false})
	}
}

func (w *Coordinator) noteCrasher(data, output []byte, hanged bool) {
	supp := extractSuppression(output)
	if _, ok := w.suppressedSigs[hash(supp)]; ok {
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
func (w *Coordinator) shutdown() {}

func extractSuppression(out []byte) []byte {
	ctx, err := stack.ParseDump(bytes.NewBuffer(out), ioutil.Discard, false)
	if err != nil {
		return out
	}

	panicLine := strings.Split(string(out), "\n")[0]
	suppression := []byte(panicLine)
	for _, gr := range ctx.Goroutines {
		if !gr.First {
			continue
		}

		// first part of suppression should include line number
		suppression = append(suppression, []byte("\n"+gr.Stack.Calls[3].FullSrcLine())...)

		for _, f := range gr.Stack.Calls[4:] {
			if f.Func.PkgDotName() == "runtime.(*Coordinator).runFuzzFunc" {
				// no longer in the the test code
				// TODO: make this less brittle
				break
			}
			suppression = append(suppression, []byte("\n"+f.Func.PkgDotName())...)
		}
		return suppression
	}

	return out
}
