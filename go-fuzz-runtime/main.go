// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gofuzzdep

import (
	"runtime"
	"syscall"
	"time"
	"unsafe"

	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-defs"
)

func RunnerMain(fns []func([]byte) int) {
	mem, inFD, outFD := setupCommFile()
	CoverTab = (*[CoverSize]byte)(unsafe.Pointer(&mem[0]))
	input := mem[CoverSize : CoverSize+MaxInputSize]
	runtime.GOMAXPROCS(1) // makes coverage more deterministic, we parallelize on higher level
	for {
		fnidx, n := 0, readInputSize(inFD) // TODO: don't hardcode functionID=0
		if n > uint64(len(input)) {
			println("invalid input length")
			syscall.Exit(1)
		}
		for i := range CoverTab {
			CoverTab[i] = 0
		}
		t0 := time.Now()
		res := fns[fnidx](input[:n:n])
		ns := time.Since(t0)
		write(outFD, uint64(res), uint64(ns))
	}
}

// read reads little-endian-encoded uint8+uint64 from fd.
func readInputSize(fd FD) uint64 {
	rd := 0
	var buf [8]byte
	for rd != len(buf) {
		n, err := fd.read(buf[rd:])
		if err == syscall.EINTR {
			continue
		}
		if n == 0 {
			syscall.Exit(1)
		}
		if err != nil {
			println("failed to read fd =", fd, "errno =", err.(syscall.Errno))
			syscall.Exit(1)
		}
		rd += n
	}
	return deserialize64(buf[:])
}

// write writes little-endian-encoded vals... to fd.
func write(fd FD, vals ...uint64) {
	var tmp [3 * 8]byte
	buf := tmp[:len(vals)*8]
	for i, v := range vals {
		serialize64(buf[i*8:], v)
	}
	wr := 0
	for wr != len(buf) {
		n, err := fd.write(buf[wr:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			println("failed to read fd =", fd, "errno =", err.(syscall.Errno))
			syscall.Exit(1)
		}
		wr += n
	}
}

// writeStr writes strings s to fd.
func writeStr(fd FD, s string) {
	buf := []byte(s)
	wr := 0
	for wr != len(buf) {
		n, err := fd.write(buf[wr:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			println("failed to read fd =", fd, "errno =", err.(syscall.Errno))
			syscall.Exit(1)
		}
		wr += n
	}
}

func serialize64(buf []byte, v uint64) uint8 {
	_ = buf[7]
	buf[0] = byte(v >> 0)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
	buf[3] = byte(v >> 24)
	buf[4] = byte(v >> 32)
	buf[5] = byte(v >> 40)
	buf[6] = byte(v >> 48)
	buf[7] = byte(v >> 56)
	return 8
}

func deserialize64(buf []byte) uint64 {
	_ = buf[7]
	return uint64(buf[0])<<0 |
		uint64(buf[1])<<8 |
		uint64(buf[2])<<16 |
		uint64(buf[3])<<24 |
		uint64(buf[4])<<32 |
		uint64(buf[5])<<40 |
		uint64(buf[6])<<48 |
		uint64(buf[7])<<56
}
