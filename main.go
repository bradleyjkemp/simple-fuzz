// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/token"
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
	flagPreserve = flag.String("preserve", "", "a comma-separated list of import paths not to instrument")
)

// main copies the package with all dependent packages into a temp dir,
// instruments Go source files there, and builds setting GOROOT to the temp dir.
func main() {
	flag.Parse()
	c := new(Context)
	pkgs := flag.Args()
	if len(pkgs) == 0 {
		pkgs = []string{"."}
	}

	c.loadPkg(pkgs)                               // load and typecheck pkg
	ignored := c.calcIgnore()                     // calculate set of packages to ignore
	c.makeWorkdir()                               // create workdir
	defer os.RemoveAll(c.workdir)                 // delete workdir
	c.populateWorkdir()                           // copy tools and packages to workdir as needed
	fuzzPackages := c.instrumentPackages(ignored) // instrument target packages and find fuzz funcs
	literals := c.gatherLiterals(ignored)
	c.createGeneratedFiles(literals, fuzzPackages) // create the files to register targets with the fuzzer

	if *flagOut == "" {
		c.runFuzzer()
	} else {
		c.buildFuzzer()
	}
}

// Context holds state for a go-fuzz-build run.
type Context struct {
	targetPackages []*packages.Package // typechecked root packages
	runtimePackage []*packages.Package // the fuzzer itself

	workdir string
}

// loadPkg loads, parses, and typechecks pkg (the package containing the Fuzz function),
// go-fuzz-dep, and their dependencies.
func (c *Context) loadPkg(targetPackages []string) {
	// Load, parse, and type-check all packages.
	// We'll use the type information later.
	// This also provides better error messages in the case
	// of invalid code than trying to compile instrumented code.
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedTypes |
			packages.NeedTypesSizes |
			packages.NeedSyntax |
			packages.NeedTypesInfo |
			packages.NeedDeps,
	}

	var err error
	c.targetPackages, err = packages.Load(cfg, targetPackages...)
	if err != nil {
		c.failf("could not load packages: %v", err)
	}

	// Stop if any package had errors.
	if packages.PrintErrors(c.targetPackages) > 0 {
		c.failf("typechecking of %v failed", targetPackages)
	}

	c.runtimePackage, err = packages.Load(cfg, "github.com/bradleyjkemp/simple-fuzz/runtime")
	if err != nil {
		c.failf("could not load runtime package: %v", err)
	}
}

// Based on isTest from GOROOT/src/cmd/go/internal/load/test.go.
// isTest tells whether name looks like a test (or benchmark, according to prefix).
// It is a Test (say) if there is a character after Test that is not a lower-case letter.
// We don't want TesticularCancer.
func isFuzzFuncName(name string) bool {
	prefix := "Fuzz"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) { // "Test" is ok
		return true
	}
	rune, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(rune)
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
	out, err := exec.Command("go", "env", "GOROOT").CombinedOutput()
	if err != nil || len(out) == 0 {
		c.failf("failed to locate GOROOT/GOPATH: 'go env' returned '%s' (%v)", out, err)
	}
	goroot := strings.Trim(string(out), "\n")
	// TODO: instead of reconstructing the world,
	// can we use a bunch of replace directives in a go.mod?

	// TODO: make all this I/O concurrent (up to a limit).
	// It's a non-trivial part of build time.
	// Question: Do it here or in copyDir?

	// TODO: See if we can avoid making toolchain copies,
	// using some combination of env vars and toolexec.
	c.copyDir(filepath.Join(goroot, "pkg", "tool"), filepath.Join(c.workdir, "pkg", "tool"))
	if _, err := os.Stat(filepath.Join(goroot, "pkg", "include")); err == nil {
		c.copyDir(filepath.Join(goroot, "pkg", "include"), filepath.Join(c.workdir, "pkg", "include"))
	} else {
		// Cross-compilation is not implemented.
		c.copyDir(filepath.Join(goroot, "pkg", runtime.GOOS+"_"+runtime.GOARCH), filepath.Join(c.workdir, "pkg", runtime.GOOS+"_"+runtime.GOARCH))
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

func (c *Context) runFuzzer() {
	cmd := exec.Command("go", "run", "-trimpath", "github.com/bradleyjkemp/simple-fuzz/runtime")
	cmd.Env = append(os.Environ(),
		"GOROOT="+filepath.Join(c.workdir),
		"GO111MODULE=off", // we have constructed a non-module, GOPATH environment
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()

	ctx := make(chan os.Signal)
	signal.Notify(ctx, os.Interrupt)
	go func() {
		sig := <-ctx
		cmd.Process.Signal(sig)
		os.RemoveAll(*flagOut)
	}()
	cmd.Wait()
}

func (c *Context) buildFuzzer() {
	cmd := exec.Command("go", "build", "-trimpath", "-o", *flagOut, "github.com/bradleyjkemp/simple-fuzz/runtime")
	cmd.Env = append(os.Environ(),
		"GOROOT="+filepath.Join(c.workdir),
		"GO111MODULE=off", // we have constructed a non-module, GOPATH environment
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		c.failf("failed to execute go build: %v\n%v", err, string(out))
	}
}

func (c *Context) calcIgnore() func(string) bool {
	ignore := map[string]bool{}
	// These are either incredibly noisy or break when instrumented

	badPackages := c.packagesNamed(
		"os",
		"syscall",
		"bytes",
	)
	packages.Visit(badPackages, func(p *packages.Package) bool {
		ignore[p.PkgPath] = true
		return true
	}, nil)

	// Ignore any packages requested explicitly by the user.
	paths := strings.Split(*flagPreserve, ",")
	for _, path := range paths {
		ignore[path] = true
	}

	return func(pkg string) bool {
		return strings.HasPrefix(pkg, "internal/") ||
			strings.HasPrefix(pkg, "runtime/") ||
			ignore[pkg]
	}
}

func (c *Context) createGeneratedFiles(literals []string, fuzzPackages []string) {
	// Runtime needs to import all packages containing a fuzz function
	runtimeDir := filepath.Join(c.workdir, "src/github.com/bradleyjkemp/simple-fuzz/runtime")
	imports := &bytes.Buffer{}
	err := importsTmpl.Execute(imports, fuzzPackages)
	if err != nil {
		c.failf("failed to execute literals template: %v", err)
	}
	c.writeFile(filepath.Join(runtimeDir, "imports.go"), imports.Bytes())

	// Write the generated file that will populate Literals
	coverageDir := filepath.Join(c.workdir, "src/github.com/bradleyjkemp/simple-fuzz/coverage")
	lits := &bytes.Buffer{}
	err = literalsTmpl.Execute(lits, literals)
	if err != nil {
		c.failf("failed to execute literals template: %v", err)
	}
	c.writeFile(filepath.Join(coverageDir, "literals.go"), lits.Bytes())
}

func (c *Context) clonePackage(p *packages.Package) {
	newDir := filepath.Join(c.workdir, "src", p.PkgPath)
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

func (c *Context) instrumentPackages(isIgnored func(string) bool) []string {
	var fuzzTargets []string
	visit := func(pkg *packages.Package) {
		c.clonePackage(pkg) // TODO: avoid copying files that are immediately re-written
		if isIgnored(pkg.PkgPath) {
			return
		}

		path := filepath.Join(c.workdir, "src", pkg.PkgPath) // TODO: need filepath.FromSlash for pkg.PkgPath?

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

			if registerFuzzFuncs(pkg.PkgPath, f) {
				if !strings.Contains(pkg.PkgPath, "/internal/") {
					// Internal packages cannot be imported directly by the runner
					// TODO: do some more codegen here to make that possible
					fuzzTargets = append(fuzzTargets, pkg.PkgPath)
				}
			}
			instrumentFile(f)
			buf := new(bytes.Buffer)
			astPrinter.Fprint(buf, pkg.Fset, f)
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
		if !ok || !isFuzzFuncName(funcDecl.Name.Name) || funcDecl.Recv != nil {
			// Shouldn't fuzz functions that aren't named FuzzCamelCase
			// or any method receivers
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
