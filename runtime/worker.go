// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"runtime/debug"
	"time"

	. "github.com/bradleyjkemp/simple-fuzz/coverage"
	"github.com/maruel/panicparse/stack"
)

func (f *Fuzzer) processInput(data []byte) {
	if len(data) > MaxInputSize {
		data = data[:MaxInputSize]
	}
	if _, ok := f.badInputs[hash(data)]; ok {
		return // don't want to run any inputs known to hang
	}

	cover, output, crashed, hanged := f.runFuzzFunc(data)
	if crashed {
		// Inputs in corpus should not crash.
		f.noteCrasher(data, output, hanged)
		return
	}

	inputcover := make([]byte, CoverSize)
	copy(inputcover, cover) // cover is shared memory so needs to be copied

	// Only want input if it hits something new
	if !compareCover(f.maxCover, inputcover) {
		return
	}

	targetCover := findNewCover(f.maxCover, inputcover)
	data = f.minimizeInput(data, false, func(candidate, cover, output []byte, crashed, hanged bool) bool {
		if crashed {
			f.noteCrasher(candidate, output, hanged)
			return false
		}
		// Minimised input is still good as long as its coverage
		// is >= the target coverage
		for loc := range cover {
			if cover[loc] < targetCover[loc] {
				return false
			}
		}
		return true
	})

	f.lastInput = time.Now()
	f.storage.addInput(data)
	updateMaxCover(f.maxCover, inputcover)
}

// processCrasher minimizes new crashers and sends them to the hub.
func (f *Fuzzer) processCrasher(crash NewCrasherArgs) {
	// Hanging inputs can take very long time to minimize.
	if !crash.Hanging {
		crash.Data = f.minimizeInput(crash.Data, true, func(candidate, cover, output []byte, crashed, hanged bool) bool {
			if !crashed {
				return false
			}
			supp := extractSuppression(output)
			if hanged || !bytes.Equal(crash.Suppression, supp) {
				f.noteCrasher(candidate, output, hanged)
				return false
			}
			crash.Error = output
			return true
		})
	}

	// New crasher from worker. Woohoo!
	if crash.Hanging || !*flagDup {
		if crash.Hanging {
			f.badInputs[hash(crash.Data)] = struct{}{}
		}
		if !*flagDup {
			f.suppressedSigs[hash(crash.Suppression)] = struct{}{}
		}
	}
	f.storage.addCrasher(crash.Data, crash.Error, crash.Hanging, crash.Suppression)
}

// minimizeInput applies series of minimizing transformations to data
// and asks pred whether the input is equivalent to the original one or not.
func (f *Fuzzer) minimizeInput(data []byte, canonicalize bool, pred func(candidate, cover, output []byte, crashed, hanged bool) bool) []byte {
	if *flagV >= 2 {
		log.Printf("worker minimizes input [%v]%x", len(data), hash(data))
	}
	res := make([]byte, len(data))
	copy(res, data)
	start := time.Now()
	shouldStopMinimizing := func() bool {
		f.broadcastStats()
		return time.Since(start) > *flagMinimize || shutdown.Err() != nil
	}

	// First, try to cut tail.
	for n := 1024; n != 0; n /= 2 {
		for len(res) > n {
			if shouldStopMinimizing() {
				return res
			}
			candidate := res[:len(res)-n]
			cover, output, crashed, hanged := f.runFuzzFunc(candidate)
			if !pred(candidate, cover, output, crashed, hanged) {
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
		cover, output, crashed, hanged := f.runFuzzFunc(candidate)
		if !pred(candidate, cover, output, crashed, hanged) {
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
			cover, output, crashed, hanged := f.runFuzzFunc(candidate)
			if !pred(candidate, cover, output, crashed, hanged) {
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
			cover, output, crashed, hanged := f.runFuzzFunc(candidate)
			if !pred(candidate, cover, output, crashed, hanged) {
				continue
			}
			res = makeCopy(candidate)
		}
	}

	return res
}

func (f *Fuzzer) runFuzzFunc(input []byte) (cover, output []byte, crashed, hanged bool) {
	f.execs++
	f.currentCandidate = input
	f.lastExec = time.Now()
	defer func() {
		err := recover()
		if err != nil {
			crashed = true
			output = []byte(fmt.Sprintf("panic: %s\n\n%s", err, debug.Stack()))
		}
	}()
	CoverTab = [CoverSize]byte{}
	f.fuzzFunc(input[0:len(input):len(input)])
	cover = (CoverTab)[:]
	return
}

func (f *Fuzzer) noteNewInput(data, cover []byte, res int) {
	if res < 0 {
		// User said to not add this input to corpus.
		return
	}
	if compareCover(f.maxCover, cover) {
		f.triageQueue = append(f.triageQueue, makeCopy(data))
	}
}

func (f *Fuzzer) noteCrasher(data, output []byte, hanged bool) {
	supp := extractSuppression(output)
	if _, ok := f.suppressedSigs[hash(supp)]; ok {
		return
	}
	f.crasherQueue = append(f.crasherQueue, NewCrasherArgs{
		Data:        makeCopy(data),
		Error:       output,
		Suppression: supp,
		Hanging:     hanged,
	})
}

func extractSuppression(out []byte) []byte {
	ctx, err := stack.ParseDump(bytes.NewBuffer(out), ioutil.Discard, false)
	if err != nil {
		return out
	}

	var suppression []byte
	for _, gr := range ctx.Goroutines {
		if !gr.First {
			continue
		}

		// first part of suppression should include line number
		suppression = append(suppression, []byte("\n"+gr.Stack.Calls[3].FullSrcLine())...)

		for _, f := range gr.Stack.Calls[4:] {
			if f.Func.PkgDotName() == "main.(*Fuzzer).runFuzzFunc" {
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
