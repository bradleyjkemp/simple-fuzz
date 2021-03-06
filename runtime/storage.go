package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type Sig [sha1.Size]byte

func hash(data []byte) Sig {
	return Sig(sha1.Sum(data))
}

type corpusItem struct {
	data           []byte
	cover          []byte
	coverFrequency *int
}

type storage struct {
	initialCorpus [][]byte
	crashersDir   string
	corpusDir     string
	crashers      map[Sig][]byte
	suppressions  map[string]bool
	corpusItems   []*corpusItem

	currentInputID    int
	currentInputCount int

	// Stores how many times each unique cover has been seen
	// Used to prioritise mutating inputs which exercise rare paths
	coverFrequencies map[Sig]*int
	lastCorpusSort   time.Time
}

type crasherMetadata struct {
	Data        []byte
	Suppression string
}

func newStorage() (*storage, error) {
	dir := "."
	crashersDir := filepath.Join(dir, "crashers")
	corpusDir := filepath.Join(dir, "corpus")
	s := &storage{
		crashersDir:      crashersDir,
		corpusDir:        corpusDir,
		crashers:         map[Sig][]byte{},
		suppressions:     map[string]bool{},
		coverFrequencies: map[Sig]*int{},
	}
	os.MkdirAll(crashersDir, 0755)
	os.MkdirAll(corpusDir, 0755)
	err := filepath.Walk(crashersDir, s.crasherWalker)
	if err != nil {
		return nil, err
	}
	err = filepath.Walk(corpusDir, s.corpusWalker)
	if err != nil {
		return nil, err
	}

	return s, nil
}

var (
	minPriority = 100
	maxPriority = 500 * minPriority
)

func (s *storage) getNextInput() []byte {
	if s.currentInputCount > 0 {
		s.currentInputCount--
		return s.corpusItems[s.currentInputID].data
	}

	s.currentInputID++
	if s.currentInputID >= len(s.corpusItems) {
		if time.Since(s.lastCorpusSort) > 10*time.Second {
			s.lastCorpusSort = time.Now()
			s.sortCorpus()
		}
		s.currentInputID = 0
	}

	maxFrequency := *s.corpusItems[0].coverFrequency
	s.currentInputCount = maxFrequency / *s.corpusItems[s.currentInputID].coverFrequency

	// Enforce a minimum number of iterations for performance reasons
	if s.currentInputCount < minPriority {
		s.currentInputCount = minPriority
	}
	// Cap the multiplier at 500x the lowest priority input to prevent starvation
	// TODO: enforce a max time mutating each input
	if s.currentInputCount > maxPriority {
		s.currentInputCount = maxPriority
	}

	return s.getNextInput()
}

var missedCoverages int
var hitCoverages int

func (s *storage) reportCoverage(cover []byte) {
	if count := s.coverFrequencies[hash(cover)]; count != nil {
		*count++
		hitCoverages++
	} else {
		missedCoverages++
	}
}

func (s *storage) addInput(input, cover []byte) error {
	coverFrequency := s.coverFrequencies[hash(cover)]
	if coverFrequency == nil {
		count := 1
		s.coverFrequencies[hash(cover)] = &count
		coverFrequency = &count
	}
	item := &corpusItem{data: input, cover: makeCopy(cover), coverFrequency: coverFrequency}
	s.corpusItems = append(s.corpusItems, item)
	filename := fmt.Sprintf("%x", hash(input))
	return ioutil.WriteFile(filepath.Join(s.corpusDir, filename), input, 0644)
}

func (s *storage) sortCorpus() {
	// Sort by decreasing coverFrequencies value (i.e. so inputs that exercise rarer paths
	// are nearer the end of the list)
	sort.Slice(s.corpusItems, func(i, j int) bool {
		return *(s.corpusItems[i].coverFrequency) > *s.corpusItems[j].coverFrequency
	})
}

func (s *storage) addCrasher(input []byte, error []byte, hanging bool, suppression []byte) {
	s.crashers[hash(input)] = input
	s.suppressions[string(suppression)] = true
	crashFileContents := &bytes.Buffer{}
	jsonMetadata, _ := json.Marshal(crasherMetadata{
		Data:        input,
		Suppression: string(suppression),
	})
	err := crasherTemplate.Execute(crashFileContents, map[string]interface{}{
		"JSON":  string(jsonMetadata),
		"Error": string(error),
		"Input": strconv.Quote(string(input)),
	})
	if err != nil {
		panic(err)
	}
	h := hash(input)
	filename := fmt.Sprintf("%x.md", h[:7])
	ioutil.WriteFile(filepath.Join(s.crashersDir, filename), crashFileContents.Bytes(), 0644)
}

// TODO: include a fully runnable example in this output
var crasherTemplate = template.Must(template.New("crasher").Parse(
	`[fuzz-crasher]: <> ({{.JSON}})
simple-fuzz detected the following crash:
` + "```" + `
{{.Error}}
` + "```" + `

When run on this input:
` + "```" + `
{{.Input}}
` + "```" + `
`))

var rCrasherMetadata = regexp.MustCompile(`(?m)^\[fuzz-crasher]: <> \((.*)\)$`)

func (s *storage) crasherWalker(path string, info os.FileInfo, err error) error {
	if info.IsDir() && path != "crashers" {
		// Only load crashers from the top level directory
		return filepath.SkipDir
	}

	if !strings.EqualFold(filepath.Ext(info.Name()), ".md") {
		return nil
	}

	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	metadata := rCrasherMetadata.FindSubmatch(contents)
	if metadata == nil {
		// This is just a markdown file without any metadata.
		// Odd (this is not generated by us) but not an error
		return nil
	}

	crasher := &crasherMetadata{}
	if err := json.Unmarshal(metadata[1], crasher); err != nil {
		// metadata existed but was invalid: probably a bad thing
		return fmt.Errorf("invalid crasher metadata: %v", err)
	}

	s.crashers[hash(crasher.Data)] = crasher.Data
	s.suppressions[crasher.Suppression] = true
	return nil
}

// Simply recursively reads all files and puts them into the corpus
func (s *storage) corpusWalker(path string, info os.FileInfo, err error) error {
	if info.IsDir() {
		return nil
	}

	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	s.initialCorpus = append(s.initialCorpus, contents)
	return nil
}
