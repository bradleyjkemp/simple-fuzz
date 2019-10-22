// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"os"

	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-defs"
	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-types"
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
		x = roundUpCover(x)
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

// Quantize the counters. Otherwise we get too inflated corpus.
func roundUpCover(x byte) byte {
	if !*flagCoverCounters && x > 0 {
		return 255
	}

	if x <= 5 {
		return x
	} else if x <= 8 {
		return 8
	} else if x <= 16 {
		return 16
	} else if x <= 32 {
		return 32
	} else if x <= 64 {
		return 64
	}
	return 255
}

func findNewCover(base, cover []byte) (res []byte, notEmpty bool) {
	res = make([]byte, CoverSize)
	for i, b := range base {
		c := cover[i]
		if c > b {
			res[i] = c
			notEmpty = true
		}
	}
	return
}

func worseCover(base, cover []byte) bool {
	for i, b := range base {
		c := cover[i]
		if c < b {
			return true
		}
	}
	return false
}

func dumpCover(outf string, blocks map[int][]CoverBlock, cover []byte) {
	// Exclude files that have no coverage at all.
	files := make(map[string]bool)
	for i, v := range cover {
		if v == 0 {
			continue
		}
		for _, b := range blocks[i] {
			files[b.File] = true
		}
	}

	out, err := os.Create(outf)
	if err != nil {
		log.Fatalf("failed to create coverage file: %v", err)
	}
	defer out.Close()
	const showCounters = false
	if showCounters {
		fmt.Fprintf(out, "mode: count\n")
	} else {
		fmt.Fprintf(out, "mode: set\n")
	}
	for i, v := range cover {
		for _, b := range blocks[i] {
			if !files[b.File] {
				continue
			}
			if !showCounters && v != 0 {
				v = 1
			}
			fmt.Fprintf(out, "%s:%v.%v,%v.%v %v %v\n",
				b.File, b.StartLine, b.StartCol, b.EndLine, b.EndCol, b.NumStmt, v)
		}
	}
}
