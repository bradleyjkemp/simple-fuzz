// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coverage

const (
	CoverSize    = 64 << 10
	MaxInputSize = 1 << 20
)

// CoverTab holds code coverage.
// It is initialized to a new array so that instrumentation
// executed during process initialization has somewhere to write to.
// It is replaced by a newly initialized array when it is
// time for actual instrumentation to commence.
var CoverTab = new([CoverSize]byte)

// PreviousLocationID stores the id of the previous coverage point.
// This is combined with the current id to decide which entry in the CoverTab
// to increment in the instrumented code.
// This is done to get a cheap approximation of path coverage instead of
// simply line coverage.
var PreviousLocationID int

// These are populated by an init() function generated during build
var Literals []string
var FuzzFunctions = map[string]func([]byte) int{}
