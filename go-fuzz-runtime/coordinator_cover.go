// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gofuzzdep

import (
	"log"

	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-coverage"
)

func makeCopy(data []byte) []byte {
	return append([]byte{}, data...)
}

func compareCover(base, cur []byte) bool {
	if len(base) != CoverSize || len(cur) != CoverSize {
		log.Fatalf("bad cover table size (%v, %v)", len(base), len(cur))
	}
	res := compareCoverDump(base, cur)
	if false {
		// This check can legitimately fail if the test process has
		// some background goroutines that continue to write to the
		// cover array (cur storage is in shared memory).
		if compareCoverDump(base, cur) != res {
			panic("bad")
		}
	}
	return res
}

func compareCoverDump(base, cur []byte) bool {
	for i, v := range base {
		if cur[i] > v {
			return true
		}
	}
	return false
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
