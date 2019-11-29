// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"log"

	. "github.com/bradleyjkemp/simple-fuzz/coverage"
)

func makeCopy(data []byte) []byte {
	return append([]byte{}, data...)
}

func (f *Fuzzer) improvesMaxCover(new []byte) bool {
	if len(new) != CoverSize {
		log.Fatalf("bad cover table size (%v)", len(new))
	}
	for i, v := range f.maxCover {
		if new[i] > v {
			return true
		}
	}
	return false
}

func findNewCover(old, new []byte) []byte {
	newCover := make([]byte, len(new))
	for loc := range new {
		if new[loc] > old[loc] {
			newCover[loc] = new[loc]
		}
	}
	return newCover
}

func updateMaxCover(base, cur []byte) int {
	if len(base) != CoverSize || len(cur) != CoverSize {
		log.Fatalf("bad cover table size (%v, %v)", len(base), len(cur))
	}
	cnt := 0
	for i, x := range cur {
		v := base[i]
		if v != 0 || x > 0 {
			cnt++
		}
		if v < x {
			base[i] = x
		}
	}
	return cnt
}
