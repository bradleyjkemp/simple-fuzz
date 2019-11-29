package main

import (
	"flag"
	"sort"

	"log"

	. "github.com/bradleyjkemp/simple-fuzz/coverage"
)

var (
	flagFunc = flag.String("func", "", "which function to fuzz")
	fuzzFunc func([]byte) int
)

func init() {
	if len(FuzzFunctions) == 0 {
		log.Fatal("No functions available to fuzz")
	}

	flag.Parse()
	if *flagFunc == "" {
		var funcs []string
		for name := range FuzzFunctions {
			funcs = append(funcs, name)
		}
		sort.Slice(funcs, func(i, j int) bool {
			return funcs[i] < funcs[j]
		})

		log.Printf("Functions available to fuzz: %v", funcs)
		*flagFunc = funcs[0]
	}

	var ok bool
	fuzzFunc, ok = FuzzFunctions[*flagFunc]
	if !ok {
		log.Fatalf("Function %s not available to fuzz", *flagFunc)
	}
	log.Printf("Fuzzing function %s", *flagFunc)
}
