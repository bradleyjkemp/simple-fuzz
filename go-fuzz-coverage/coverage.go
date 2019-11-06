// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package go_fuzz_coverage

const (
	CoverSize       = 64 << 10
	MaxInputSize    = 1 << 20
	SonarRegionSize = 1 << 20
)

// CoverTab holds code coverage.
// It is initialized to a new array so that instrumentation
// executed during process initialization has somewhere to write to.
// It is replaced by a newly initialized array when it is
// time for actual instrumentation to commence.
var CoverTab = new([CoverSize]byte)
