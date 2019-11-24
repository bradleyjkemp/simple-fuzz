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
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/packages"
)

var (
	flagOut      = flag.String("o", "", "if set, output the fuzzer binary to this file instead of running it")
	shouldRun    = false
	flagPreserve = flag.String("preserve", "", "a comma-separated list of import paths not to instrument")
)

// basePackagesConfig returns a base golang.org/x/tools/go/packages.Config
// that clients can then modify and use for calls to go/packages.
func basePackagesConfig() *packages.Config {
	cfg := new(packages.Config)
	cfg.Env = os.Environ()
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

	c.loadPkg(pkg)                // load and typecheck pkg
	c.getEnv()                    // discover GOROOT, GOPATH
	c.loadStd()                   // load standard library
	c.calcIgnore()                // calculate set of packages to ignore
	c.makeWorkdir()               // create workdir
	defer os.RemoveAll(c.workdir) // delete workdir
	c.populateWorkdir()           // copy tools and packages to workdir as needed

	if *flagOut == "" {
		*flagOut = filepath.Join(os.TempDir(), c.targetPackages[0].Name+"-fuzz")
		shouldRun = true
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
	if shouldRun {
		cmd := exec.Command(*flagOut)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Start()

		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt)
		go func() {
			sig := <-c
			cmd.Process.Signal(sig)
			os.RemoveAll(*flagOut)
		}()
		cmd.Wait()
	}
}

// Context holds state for a go-fuzz-build run.
type Context struct {
	targetPackages []*packages.Package // typechecked root packages
	runtimePackage []*packages.Package // the fuzzer itself

	std    map[string]bool // set of packages in the standard library
	ignore map[string]bool // set of packages to ignore during instrumentation

	workdir string
	GOROOT  string
	GOPATH  string
}

func (c *Context) isIgnored(pkg string) bool {
	return strings.HasPrefix(pkg, "internal/") ||
		strings.HasPrefix(pkg, "runtime/") ||
		c.ignore[pkg]
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
}

// loadPkg loads, parses, and typechecks pkg (the package containing the Fuzz function),
// go-fuzz-dep, and their dependencies.
func (c *Context) loadPkg(pkg string) {
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
	var err error
	c.targetPackages, err = packages.Load(cfg, pkg)
	if err != nil {
		c.failf("could not load packages: %v", err)
	}

	// Stop if any package had errors.
	if packages.PrintErrors(c.targetPackages) > 0 {
		c.failf("typechecking of %v failed", pkg)
	}

	c.runtimePackage, err = packages.Load(cfg, "github.com/bradleyjkemp/simple-fuzz/runtime")
	if err != nil {
		c.failf("cloud not load runtime package: %v", err)
	}
}

// isFuzzSig reports whether sig is of the form
//   func FuzzFunc(data []byte) int
func isFuzzSig(sig *types.Signature) bool {
	return sig.Params().Len() == 1 && sig.Params().At(0).Type().String() == "[]byte" &&
		sig.Results().Len() == 1 && sig.Results().At(0).Type().String() == "int"
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
	packages.Visit(c.runtimePackage, nil, func(p *packages.Package) {
		c.clonePackage(p)
	})
}

func (c *Context) buildInstrumentedBinary() {
	fuzzPackages := c.instrumentPackages()
	c.copyFuzzDep(fuzzPackages)
	cmd := exec.Command("go", "build", "-trimpath", "-o", *flagOut, "github.com/bradleyjkemp/simple-fuzz/runtime")
	cmd.Env = append(os.Environ(),
		"GOROOT="+filepath.Join(c.workdir, "goroot"),
		"GOPATH="+filepath.Join(c.workdir, "gopath"),
		"GO111MODULE=off", // we have constructed a non-module, GOPATH environment
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		c.failf("failed to execute go build: %v\n%v", err, string(out))
	}
}

func (c *Context) calcIgnore() {
	c.ignore = map[string]bool{}
	// These are either incredibly noisy or break when instrumented
	badPackages := c.packagesNamed(
		"os",
		"syscall",
		"bytes",
	)
	packages.Visit(badPackages, func(p *packages.Package) bool {
		c.ignore[p.PkgPath] = true
		return true
	}, nil)

	// Ignore any packages requested explicitly by the user.
	paths := strings.Split(*flagPreserve, ",")
	for _, path := range paths {
		c.ignore[path] = true
	}
}

func (c *Context) copyFuzzDep(fuzzPackages []string) {
	// Standard library packages can't depend on non-standard ones.
	// So we pretend that go-fuzz-dep is a standard one.
	// go-fuzz-dep depends on go-fuzz-coverage, which creates a problem.
	// Fortunately (and intentionally), go-fuzz-coverage contains only constants,
	// which can be duplicated safely.
	// So we eliminate the import statement and copy go-fuzz-coverage/defs.go
	// directly into the go-fuzz-dep package.
	runtimeDir := filepath.Join(c.workdir, "gopath", "src", "github.com", "bradleyjkemp", "simple-fuzz", "runtime")
	c.mkdirAll(runtimeDir)
	dep := c.packageNamed("github.com/bradleyjkemp/simple-fuzz/runtime")
	for _, f := range dep.GoFiles {
		data := c.readFile(f)
		// Eliminate the dot import.
		data = bytes.Replace(data, []byte(`. "github.com/bradleyjkemp/simple-fuzz/coverage"`), []byte(`. "coverage"`), -1)
		c.writeFile(filepath.Join(runtimeDir, filepath.Base(f)), data)
	}

	// Runtime also needs to import all packages containing a fuzz function
	imports := &bytes.Buffer{}
	err := importsTmpl.Execute(imports, fuzzPackages)
	if err != nil {
		c.failf("failed to execute literals template: %v", err)
	}
	c.writeFile(filepath.Join(runtimeDir, "imports.go"), imports.Bytes())

	coverageDir := filepath.Join(c.workdir, "goroot", "src", "coverage")
	c.mkdirAll(coverageDir)
	defs := c.packageNamed("github.com/bradleyjkemp/simple-fuzz/coverage")
	for _, f := range defs.GoFiles {
		data := c.readFile(f)
		c.writeFile(filepath.Join(coverageDir, filepath.Base(f)), data)
	}
	// Now write the generated files that will populate Literals and Funcs
	lits := &bytes.Buffer{}
	err = literalsTmpl.Execute(lits, c.gatherLiterals())
	if err != nil {
		c.failf("failed to execute literals template: %v", err)
	}
	c.writeFile(filepath.Join(coverageDir, "literals.go"), lits.Bytes())
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
	if len(all) == 0 {
		c.failf("got no packages matching %v", path)
	}
	if len(all) > 1 {
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
	packages.Visit(append(c.targetPackages, c.runtimePackage...), pre, nil)
	return pkgs
}

func (c *Context) instrumentPackages() []string {
	var fuzzTargets []string
	visit := func(pkg *packages.Package) {
		c.clonePackage(pkg) // TODO: avoid copying files that are immediately re-written
		if c.isIgnored(pkg.PkgPath) {
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

			removeUnnecessaryComments(f, pkg.Fset)

			buf := new(bytes.Buffer)
			if registerFuzzFuncs(pkg.PkgPath, f) {
				if !strings.Contains(pkg.PkgPath, "/internal/") {
					// Internal packages cannot be imported directly by the runner
					// TODO: do some more codegen here to make that possible
					fuzzTargets = append(fuzzTargets, pkg.PkgPath)
				}
			}
			instrument(pkg.Fset, f, buf)
			outpath := filepath.Join(path, fname)
			c.writeFile(outpath, buf.Bytes())
		}
	}

	packages.Visit(c.targetPackages, nil, visit)
	return fuzzTargets
}

func registerFuzzFuncs(pkg string, f *ast.File) bool {
	// test if there are any fuzz functions and if so register them with the runtime
	var fuzzFuncs []ast.Stmt
	for _, d := range f.Decls {
		funcDecl, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}

		if !isFuzzFuncName(funcDecl.Name.Name) || funcDecl.Recv != nil {
			// Shouldn't fuzz functions that aren't named FuzzCamelCase
			// or any method receivers
			continue
		}

		params := funcDecl.Type.Params.List
		if len(params) != 1 {
			// Doesn't have exactly one parameter
			continue
		}
		param, ok := params[0].Type.(*ast.ArrayType)
		if !ok || param.Len != nil {
			// First param needs to be a slice type
			continue
		}

		sliceType, ok := param.Elt.(*ast.Ident)
		if !ok || sliceType.Name != "byte" {
			// slice type is something odd like []struct{foo string}
			continue
		}

		// Generates: fuzzdepPkg.FuzzFunctions[pkg.name] = func
		fuzzFuncs = append(fuzzFuncs, &ast.AssignStmt{
			Lhs: []ast.Expr{
				&ast.IndexExpr{
					X: &ast.SelectorExpr{
						X: &ast.Ident{Name: fuzzdepPkg},
						Sel: &ast.Ident{
							Name: "FuzzFunctions",
						},
					},
					Index: &ast.BasicLit{
						Kind:  token.STRING,
						Value: fmt.Sprintf(`"%s.%s"`, pkg, funcDecl.Name.Name),
					},
				},
			},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{funcDecl.Name},
		})
	}

	if len(fuzzFuncs) > 0 {
		// Add an init() function with all of the individual registrations
		// Go allows multiple init() functions in the same package/file so
		// no need to check if one already exists
		f.Decls = append(f.Decls, &ast.FuncDecl{
			Name: &ast.Ident{
				Name: "init",
			},
			Type: &ast.FuncType{
				Params:  &ast.FieldList{},
				Results: nil,
			},
			Body: &ast.BlockStmt{
				List: fuzzFuncs,
			},
		})
		return true
	}
	return false
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
	contents, err := ioutil.ReadFile(src)
	if err != nil {
		c.failf("copyFile: could not read %v", src, err)
	}
	if err := ioutil.WriteFile(dst, contents, 0700); err != nil {
		c.failf("copyFile: could not write %v: %v", dst, err)
	}
}

func (c *Context) failf(str string, args ...interface{}) {
	os.RemoveAll(c.workdir)
	fmt.Fprintf(os.Stderr, str+"\n", args...)
	os.Exit(1)
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

var importsTmpl = template.Must(template.New("imports").Parse(`
package main

import (
{{range .}}	_ "{{.}}"
{{end}}
)
`))

var literalsTmpl = template.Must(template.New("main").Parse(`
package coverage

func init() {
	Literals = []string{
{{range .}}	{{.}},
{{end}}
	}
}

`))
