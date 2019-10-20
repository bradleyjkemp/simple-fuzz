// Copyright 2019 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build gofuzz

package gofuzzdep

import (
	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-defs"
)

// Bool is just a bool.
// It is used by code autogenerated by go-fuzz-build
// to avoid compilation errors when a user's code shadows the built-in bool.
type Bool = bool

// CoverTab holds code coverage.
// It is initialized to a new array so that instrumentation
// executed during process initialization has somewhere to write to.
// It is replaced by a newly initialized array when it is
// time for actual instrumentation to commence.
var CoverTab = new([CoverSize]byte)
