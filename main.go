// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/packages"
)

var (
	flagOut      = flag.String("o", "", "output file")
	flagFunc     = flag.String("func", "", "preferred entry function")
	flagWork     = flag.Bool("work", false, "don't remove working directory")
	flagCPU      = flag.Bool("cpuprofile", false, "generate cpu profile in cpu.pprof")
	flagBuildX   = flag.Bool("x", false, "print the commands if build fails")
	flagPreserve = flag.String("preserve", "", "a comma-separated list of import paths not to instrument")
)

// basePackagesConfig returns a base golang.org/x/tools/go/packages.Config
// that clients can then modify and use for calls to go/packages.
func basePackagesConfig() *packages.Config {
	cfg := new(packages.Config)

	goFuzzModule, isGoFuzzModuleSet := os.LookupEnv("GOFUZZ111MODULE")
	if isGoFuzzModuleSet {
		cfg.Env = append(os.Environ(), "GO111MODULE="+goFuzzModule)
	} else {
		cfg.Env = append(os.Environ(), "GO111MODULE=off")
	}
	return cfg
}

// main copies the package with all dependent packages into a temp dir,
// instruments Go source files there, and builds setting GOROOT to the temp dir.
func main() {
	flag.Parse()
	c := new(Context)

	if flag.NArg() > 1 {
		c.failf("usage: go-fuzz-build [pkg]")
	}

	pkg := "."
	if flag.NArg() == 1 {
		pkg = flag.Arg(0)
	}
	if *flagFunc != "" && !isFuzzFuncName(*flagFunc) {
		c.failf("provided -func=%v, but %v is not a fuzz function name", *flagFunc, *flagFunc)
	}

	c.startProfiling()  // start pprof as requested
	c.loadPkg(pkg)      // load and typecheck pkg
	c.getEnv()          // discover GOROOT, GOPATH
	c.loadStd()         // load standard library
	c.calcIgnore()      // calculate set of packages to ignore
	c.makeWorkdir()     // create workdir
	defer c.cleanup()   // delete workdir as needed, etc.
	c.populateWorkdir() // copy tools and packages to workdir as needed

	if *flagOut == "" {
		*flagOut = c.pkgs[0].Name + "-fuzz"
	}

	// Gather literals, instrument, and compile.
	// Order matters here!
	// buildInstrumentedBinary (and instrumentPackages) modify the AST.
	// (We don't want to re-parse and re-typecheck every time, for performance.)
	// So we gather literals first, while the AST is pristine.
	// Then we add coverage and build.
	// Then we add sonar and build.
	// TODO: migrate to use cmd/internal/edit instead of AST modification.
	// This has several benefits: (1) It is easier to work with.
	// (2) 'go cover' has switched to it; we would get the benefit of
	// upstream bug fixes, of which there has been at least one (around gotos and labels).
	// (3) It leaves the AST intact, so we are less order-sensitive.
	// The primary blocker is that we want good line numbers for when we find crashers.
	// go/printer handles this automatically using Mode printer.SourcePos.
	// We'd need to implement that support ourselves. (It's do-able but non-trivial.)
	// See also https://golang.org/issue/29824.
	c.buildInstrumentedBinary()
}

// Context holds state for a go-fuzz-build run.
type Context struct {
	fuzzpkg *packages.Package   // package containing Fuzz function
	pkgs    []*packages.Package // typechecked root packages

	std    map[string]bool // set of packages in the standard library
	ignore map[string]bool // set of packages to ignore during instrumentation

	allFuncs []string // all fuzz functions found in package

	workdir string
	GOROOT  string
	GOPATH  string

	cpuprofile *os.File

	cmdGoHasTrimPath bool // does the active version of cmd/go have the -trimpath flag?
}

// getEnv determines GOROOT and GOPATH and updates c accordingly.
func (c *Context) getEnv() {
	env := map[string]string{
		"GOROOT": "",
		"GOPATH": "",
	}
	for k := range env {
		v := os.Getenv(k)
		if v != "" {
			env[k] = v
			continue
		}
		// TODO: make a single call ("go env GOROOT GOPATH") instead
		out, err := exec.Command("go", "env", k).CombinedOutput()
		if err != nil || len(out) == 0 {
			c.failf("%s is not set and failed to locate it: 'go env %s' returned '%s' (%v)", k, k, out, err)
		}
		env[k] = strings.TrimSpace(string(out))
	}
	c.GOROOT = env["GOROOT"]
	c.GOPATH = env["GOPATH"]

	out, err := exec.Command("go", "list", "-f", "'{{context.ReleaseTags}}'", "runtime").CombinedOutput()
	if err != nil || len(out) == 0 {
		c.failf("go list -f '{{context.ReleaseTags}}' runtime returned '%s' (%v)", out, err)
	}
	c.cmdGoHasTrimPath = bytes.Contains(out, []byte("go1.13"))
}

// startProfiling starts pprof profiling, if requested.
func (c *Context) startProfiling() {
	if !*flagCPU {
		return
	}
	var err error
	c.cpuprofile, err = os.Create("cpu.pprof")
	if err != nil {
		c.failf("could not create cpu profile: %v", err)
	}
	pprof.StartCPUProfile(c.cpuprofile)
}

// loadPkg loads, parses, and typechecks pkg (the package containing the Fuzz function),
// go-fuzz-dep, and their dependencies.
func (c *Context) loadPkg(pkg string) {
	// Resolve pkg.
	// See https://golang.org/issue/30826 and https://golang.org/issue/30828.
	rescfg := basePackagesConfig()
	rescfg.Mode = packages.NeedName
	respkgs, err := packages.Load(rescfg, pkg)
	if err != nil {
		c.failf("could not resolve package %q: %v", pkg, err)
	}
	if len(respkgs) != 1 {
		paths := make([]string, len(respkgs))
		for i, p := range respkgs {
			paths[i] = p.PkgPath
		}
		c.failf("cannot build multiple packages, but %q resolved to: %v", pkg, strings.Join(paths, ", "))
	}
	if respkgs[0].Name == "main" {
		c.failf("cannot fuzz package main")
	}
	pkgpath := respkgs[0].PkgPath

	// Load, parse, and type-check all packages.
	// We'll use the type information later.
	// This also provides better error messages in the case
	// of invalid code than trying to compile instrumented code.
	cfg := basePackagesConfig()
	cfg.Mode = packages.LoadAllSyntax
	// use custom ParseFile in order to get comments
	cfg.ParseFile = func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
		return parser.ParseFile(fset, filename, src, parser.ParseComments)
	}
	// We need to load:
	// * the target package, obviously
	// * go-fuzz-runtime, since we use it for instrumentation
	// * reflect, if we are using libfuzzer, since its generated main function requires it
	loadpkgs := []string{pkg, "github.com/bradleyjkemp/simple-fuzz/go-fuzz-runtime"}
	initial, err := packages.Load(cfg, loadpkgs...)
	if err != nil {
		c.failf("could not load packages: %v", err)
	}

	// Stop if any package had errors.
	if packages.PrintErrors(initial) > 0 {
		c.failf("typechecking of %v failed", pkg)
	}

	c.pkgs = initial

	// Find the fuzz package among c.pkgs.
	for _, p := range initial {
		if p.PkgPath == pkgpath {
			c.fuzzpkg = p
			break
		}
	}
	if c.fuzzpkg == nil {
		c.failf("internal error: failed to find fuzz package; please file an issue")
	}

	// Find all fuzz functions in fuzzpkg.
	foundFlagFunc := false
	s := c.fuzzpkg.Types.Scope()
	for _, n := range s.Names() {
		if !isFuzzFuncName(n) {
			continue
		}
		// Check that n is a function with an appropriate signature.
		typ := s.Lookup(n).Type()
		sig, ok := typ.(*types.Signature)
		if !ok || sig.Variadic() || !isFuzzSig(sig) {
			if n == *flagFunc {
				c.failf("provided -func=%v, but %v is not a fuzz function", *flagFunc, *flagFunc)
			}
			continue
		}
		// n is a fuzz function.
		c.allFuncs = append(c.allFuncs, n)
		foundFlagFunc = foundFlagFunc || n == *flagFunc
	}

	if len(c.allFuncs) == 0 {
		c.failf("could not find any fuzz functions in %v", c.fuzzpkg.PkgPath)
	}
	if len(c.allFuncs) > 255 {
		c.failf("go-fuzz-build supports a maximum of 255 fuzz functions, found %v; please file an issue", len(c.allFuncs))
	}

	if *flagFunc != "" {
		// Specific fuzz function requested.
		// If the requested function doesn't exist, fail.
		if !foundFlagFunc {
			c.failf("could not find fuzz function %v in %v", *flagFunc, c.fuzzpkg.PkgPath)
		}
	} else {
		// No specific fuzz function requested.
		// If there's only one fuzz function, mark it as preferred.
		// If there's more than one...
		//   ...for go-fuzz, that's fine; one can be specified later on the command line.
		//   ...for libfuzzer, that's not fine, as there is no way to specify one later.
		if len(c.allFuncs) == 1 {
			*flagFunc = c.allFuncs[0]
		}
	}
}

// isFuzzSig reports whether sig is of the form
//   func FuzzFunc(data []byte) int
func isFuzzSig(sig *types.Signature) bool {
	return tupleHasTypes(sig.Params(), "[]byte") && tupleHasTypes(sig.Results(), "int")
}

// tupleHasTypes reports whether tuple is composed of
// elements with exactly the types in types.
func tupleHasTypes(tuple *types.Tuple, types ...string) bool {
	if tuple.Len() != len(types) {
		return false
	}
	for i, t := range types {
		if tuple.At(i).Type().String() != t {
			return false
		}
	}
	return true
}

func isFuzzFuncName(name string) bool {
	return isTest(name, "Fuzz")
}

// isTest is copied verbatim, along with its name,
// from GOROOT/src/cmd/go/internal/load/test.go.
// isTest tells whether name looks like a test (or benchmark, according to prefix).
// It is a Test (say) if there is a character after Test that is not a lower-case letter.
// We don't want TesticularCancer.
func isTest(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) { // "Test" is ok
		return true
	}
	rune, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(rune)
}

// loadStd finds the set of standard library package paths.
func (c *Context) loadStd() {
	// Find out what packages are in the standard library.
	cfg := basePackagesConfig()
	cfg.Mode = packages.NeedName
	stdpkgs, err := packages.Load(cfg, "std")
	if err != nil {
		c.failf("could not load standard library: %v", err)
	}
	c.std = make(map[string]bool, len(stdpkgs))
	for _, p := range stdpkgs {
		c.std[p.PkgPath] = true
	}
}

// makeWorkdir creates the workdir, logging as requested.
func (c *Context) makeWorkdir() {
	// TODO: make workdir stable, so that we can use cmd/go's build cache?
	// See https://github.com/golang/go/issues/29430.
	var err error
	c.workdir, err = ioutil.TempDir("", "go-fuzz-build")
	if err != nil {
		c.failf("failed to create temp dir: %v", err)
	}
	if *flagWork {
		fmt.Printf("workdir: %v\n", c.workdir)
	}
}

// cleanup ensures a clean exit. It should be called on all (controllable) exit paths.
func (c *Context) cleanup() {
	if !*flagWork && c.workdir != "" {
		os.RemoveAll(c.workdir)
	}
	if c.cpuprofile != nil {
		pprof.StopCPUProfile()
		c.cpuprofile.Close()
	}
}

// populateWorkdir prepares workdir for builds.
func (c *Context) populateWorkdir() {
	// TODO: instead of reconstructing the world,
	// can we use a bunch of replace directives in a go.mod?

	// TODO: make all this I/O concurrent (up to a limit).
	// It's a non-trivial part of build time.
	// Question: Do it here or in copyDir?

	// TODO: See if we can avoid making toolchain copies,
	// using some combination of env vars and toolexec.
	c.copyDir(filepath.Join(c.GOROOT, "pkg", "tool"), filepath.Join(c.workdir, "goroot", "pkg", "tool"))
	if _, err := os.Stat(filepath.Join(c.GOROOT, "pkg", "include")); err == nil {
		c.copyDir(filepath.Join(c.GOROOT, "pkg", "include"), filepath.Join(c.workdir, "goroot", "pkg", "include"))
	} else {
		// Cross-compilation is not implemented.
		c.copyDir(filepath.Join(c.GOROOT, "pkg", runtime.GOOS+"_"+runtime.GOARCH), filepath.Join(c.workdir, "goroot", "pkg", runtime.GOOS+"_"+runtime.GOARCH))
	}

	// Clone our package, go-fuzz-deps, and all dependencies.
	// TODO: we might not need to do this for all packages.
	// We know that we'll be writing out instrumented Go code later;
	// we could instead just os.MkdirAll and copy non-Go files here.
	// We'd still need to do a full package clone for packages that
	// we aren't instrumenting (c.ignore).
	packages.Visit(c.pkgs, nil, func(p *packages.Package) {
		c.clonePackage(p)
	})
	c.copyFuzzDep()
}

func (c *Context) buildInstrumentedBinary() {
	c.instrumentPackages()
	mainPkg := c.createFuzzMain()
	args := []string{"build"}
	if *flagBuildX {
		args = append(args, "-x")

		if *flagWork {
			args = append(args, "-work")
		}
	}
	if c.cmdGoHasTrimPath {
		args = append(args, "-trimpath")
	}
	args = append(args, "-o", *flagOut, mainPkg)
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(),
		"GOROOT="+filepath.Join(c.workdir, "goroot"),
		"GOPATH="+filepath.Join(c.workdir, "gopath"),
		"GO111MODULE=off", // temporary measure until we have proper module support
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		c.failf("failed to execute go build: %v\n%v", err, string(out))
	}
}

func (c *Context) calcIgnore() {
	// No reason to instrument these.
	c.ignore = map[string]bool{
		"runtime/cgo":   true,
		"runtime/pprof": true,
		"runtime/race":  true,
	}

	// Roots: must not instrument these, nor any of their dependencies, to avoid import cycles.
	// Fortunately, these are mostly packages that are non-deterministic,
	// noisy (because they are low level), and/or not interesting.
	// We could manually maintain this list, but that makes go-fuzz-build
	// fragile in the face of internal standard library package changes.
	roots := c.packagesNamed("runtime", "github.com/bradleyjkemp/simple-fuzz/go-fuzz-runtime")
	packages.Visit(roots, func(p *packages.Package) bool {
		c.ignore[p.PkgPath] = true
		return true
	}, nil)

	// Ignore any packages requested explicitly by the user.
	paths := strings.Split(*flagPreserve, ",")
	for _, path := range paths {
		c.ignore[path] = true
	}
}

func (c *Context) gatherLiterals() []string {
	nolits := map[string]bool{
		"math":    true,
		"os":      true,
		"unicode": true,
	}

	lits := make(map[string]struct{})
	visit := func(pkg *packages.Package) {
		if c.ignore[pkg.PkgPath] || nolits[pkg.PkgPath] {
			return
		}
		for _, f := range pkg.Syntax {
			ast.Walk(&LiteralCollector{lits: lits, ctxt: c}, f)
		}
	}

	packages.Visit(c.pkgs, nil, visit)

	litsList := make([]string, 0, len(lits))
	for lit, _ := range lits {
		litsList = append(litsList, lit)
	}
	return litsList
}

func (c *Context) copyFuzzDep() {
	// Standard library packages can't depend on non-standard ones.
	// So we pretend that go-fuzz-dep is a standard one.
	// go-fuzz-dep depends on go-fuzz-coverage, which creates a problem.
	// Fortunately (and intentionally), go-fuzz-coverage contains only constants,
	// which can be duplicated safely.
	// So we eliminate the import statement and copy go-fuzz-coverage/defs.go
	// directly into the go-fuzz-dep package.
	newDir := filepath.Join(c.workdir, "gopath", "src", "github.com", "bradleyjkemp", "simple-fuzz", "go-fuzz-runtime")
	c.mkdirAll(newDir)
	dep := c.packageNamed("github.com/bradleyjkemp/simple-fuzz/go-fuzz-runtime")
	for _, f := range dep.GoFiles {
		data := c.readFile(f)
		// Eliminate the dot import.
		data = bytes.Replace(data, []byte(`. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-coverage"`), []byte(`. "go-fuzz-coverage"`), -1)
		c.writeFile(filepath.Join(newDir, filepath.Base(f)), data)
	}

	newDir = filepath.Join(c.workdir, "goroot", "src", "go-fuzz-coverage")
	c.mkdirAll(newDir)
	defs := c.packageNamed("github.com/bradleyjkemp/simple-fuzz/go-fuzz-coverage")
	for _, f := range defs.GoFiles {
		data := c.readFile(f)
		c.writeFile(filepath.Join(newDir, filepath.Base(f)), data)
	}
}

func (c *Context) createFuzzMain() string {
	mainPkg := filepath.Join(c.fuzzpkg.PkgPath, "go.fuzz.main")
	path := filepath.Join(c.workdir, "gopath", "src", mainPkg)
	c.mkdirAll(path)

	dot := map[string]interface{}{"Pkg": c.fuzzpkg.PkgPath, "AllFuncs": c.allFuncs, "DefaultFunc": *flagFunc, "Literals": c.gatherLiterals()}
	buf := new(bytes.Buffer)
	if err := mainSrc.Execute(buf, dot); err != nil {
		c.failf("could not execute template: %v", err)
	}
	c.writeFile(filepath.Join(path, "main.go"), buf.Bytes())
	return mainPkg
}

func (c *Context) clonePackage(p *packages.Package) {
	root := "goroot"
	if !c.std[p.PkgPath] {
		root = "gopath"
	}
	newDir := filepath.Join(c.workdir, root, "src", p.PkgPath)
	c.mkdirAll(newDir)

	if p.PkgPath == "unsafe" {
		// Write a dummy file. go/packages explicitly returns an empty GoFiles for it,
		// for reasons that are unclear, but cmd/go wants there to be a Go file in the package.
		c.writeFile(filepath.Join(newDir, "unsafe.go"), []byte(`package unsafe`))
		return
	}

	// Copy all the source code.

	// Use GoFiles instead of CompiledGoFiles here.
	// If we use CompiledGoFiles, we end up with code that cmd/go won't compile.
	// See https://golang.org/issue/30479 and Context.instrumentPackages.
	for _, f := range p.GoFiles {
		dst := filepath.Join(newDir, filepath.Base(f))
		c.copyFile(f, dst)
	}
	for _, f := range p.OtherFiles {
		dst := filepath.Join(newDir, filepath.Base(f))
		c.copyFile(f, dst)
	}

	// TODO: do we need to look for and copy go.mod?
}

// packageNamed extracts the package listed in path.
func (c *Context) packageNamed(path string) (pkgs *packages.Package) {
	all := c.packagesNamed(path)
	if len(all) != 1 {
		c.failf("got multiple packages, requested only %v", path)
	}
	return all[0]
}

// packagesNamed extracts the packages listed in paths.
func (c *Context) packagesNamed(paths ...string) (pkgs []*packages.Package) {
	pre := func(p *packages.Package) bool {
		for _, path := range paths {
			if p.PkgPath == path {
				pkgs = append(pkgs, p)
				break
			}
		}
		return len(pkgs) < len(paths) // continue only if we have not succeeded yet
	}
	packages.Visit(c.pkgs, pre, nil)
	return pkgs
}

func (c *Context) instrumentPackages() {
	visit := func(pkg *packages.Package) {
		if c.ignore[pkg.PkgPath] {
			return
		}

		root := "goroot"
		if !c.std[pkg.PkgPath] {
			root = "gopath"
		}
		path := filepath.Join(c.workdir, root, "src", pkg.PkgPath) // TODO: need filepath.FromSlash for pkg.PkgPath?

		for i, fullName := range pkg.CompiledGoFiles {
			fname := filepath.Base(fullName)
			if !strings.HasSuffix(fname, ".go") {
				// This is a cgo-generated file.
				// Instrumenting it currently does not work.
				// We copied the original Go file as part of copyPackageRewrite,
				// so we can just skip this one.
				// See https://golang.org/issue/30479.
				continue
			}
			f := pkg.Syntax[i]

			// TODO: rename trimComments?
			f.Comments = trimComments(f, pkg.Fset)

			buf := new(bytes.Buffer)
			content := c.readFile(fullName)
			buf.Write(initialComments(content)) // Retain '// +build' directives.
			instrument(pkg.PkgPath, fullName, pkg.Fset, f, pkg.TypesInfo, buf)
			tmp := c.tempFile()
			c.writeFile(tmp, buf.Bytes())
			outpath := filepath.Join(path, fname)
			if runtime.GOOS == "windows" {
				os.Remove(outpath)
			}
			c.moveFile(tmp, outpath)
		}
	}

	packages.Visit(c.pkgs, nil, visit)
}

func (c *Context) copyDir(dir, newDir string) {
	c.mkdirAll(newDir)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		c.failf("failed to scan dir '%v': %v", dir, err)
	}
	for _, f := range files {
		if f.IsDir() {
			c.copyDir(filepath.Join(dir, f.Name()), filepath.Join(newDir, f.Name()))
			continue
		}
		src := filepath.Join(dir, f.Name())
		dst := filepath.Join(newDir, f.Name())
		c.copyFile(src, dst)
	}
}

func (c *Context) copyFile(src, dst string) {
	r, err := os.Open(src)
	if err != nil {
		c.failf("copyFile: could not read %v", src, err)
	}
	w, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		c.failf("copyFile: could not write %v: %v", dst, err)
	}
	if _, err := io.Copy(w, r); err != nil {
		c.failf("copyFile: copying failed: %v", err)
	}
	if err := r.Close(); err != nil {
		c.failf("copyFile: closing %v failed: %v", src, err)
	}
	if err := w.Close(); err != nil {
		c.failf("copyFile: closing %v failed: %v", dst, err)
	}
}

func (c *Context) moveFile(src, dst string) {
	c.copyFile(src, dst)
	err := os.Remove(src)
	if err != nil {
		c.failf("moveFile: removing %q failed: %v", src, err)
	}
}

func (c *Context) failf(str string, args ...interface{}) {
	c.cleanup()
	fmt.Fprintf(os.Stderr, str+"\n", args...)
	os.Exit(1)
}

// tempFile creates and deletes a temp file, and returns its path.
// This is helpful when you need a temp path for an output file
// that will be created by an external tool (go build) or by a call to writeFile.
func (c *Context) tempFile() string {
	outf, err := ioutil.TempFile("", "go-fuzz")
	if err != nil {
		c.failf("failed to create temp file: %v", err)
	}
	outf.Close()
	os.Remove(outf.Name()) // necessary on Windows
	return outf.Name()
}

func (c *Context) readFile(name string) []byte {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		c.failf("failed to read temp file: %v", err)
	}
	return data
}

func (c *Context) writeFile(name string, data []byte) {
	if err := ioutil.WriteFile(name, data, 0700); err != nil {
		c.failf("failed to write temp file: %v", err)
	}
}

func (c *Context) mkdirAll(dir string) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		c.failf("failed to create temp dir: %v", err)
	}
}

var mainSrc = template.Must(template.New("main").Parse(`
package main

import (
	target "{{.Pkg}}"
	dep "github.com/bradleyjkemp/simple-fuzz/go-fuzz-runtime"
	"flag"
)

var (
	flagCoordinator = flag.Bool("coordinator", true, "whether this is the coordinator or the runner")
)

var (
	literals = []string{
		{{range .Literals}}{{.}},
{{end}}
	}
)

func main() {
	flag.Parse()
	if *flagCoordinator {
		dep.CoordinatorMain(literals)
	} else {
		fns := []func([]byte)int {
			{{range .AllFuncs}}
				target.{{.}},
			{{end}}
		}
		dep.RunnerMain(fns)
	}
}
`))