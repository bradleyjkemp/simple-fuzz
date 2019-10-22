// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"go/types"
	"io"
	"strconv"
	"strings"

	. "github.com/bradleyjkemp/simple-fuzz/go-fuzz-types"
)

const fuzzdepPkg = "_go_fuzz_dep_"

func instrument(pkg, fullName string, fset *token.FileSet, parsedFile *ast.File, info *types.Info, out io.Writer, blocks *[]CoverBlock) {
	file := &File{
		fset:     fset,
		pkg:      pkg,
		fullName: fullName,
		astFile:  parsedFile,
		blocks:   blocks,
		info:     info,
	}
	file.addImport("go-fuzz-dep", fuzzdepPkg, "CoverTab")
	ast.Walk(file, file.astFile)
	file.print(out)
}

type LiteralCollector struct {
	ctxt *Context
	lits map[Literal]struct{}
}

func (lc *LiteralCollector) Visit(n ast.Node) (w ast.Visitor) {
	switch nn := n.(type) {
	default:
		return lc // recurse
	case *ast.ImportSpec:
		return nil
	case *ast.Field:
		return nil // ignore field tags
	case *ast.CallExpr:
		switch fn := nn.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "panic" {
				return nil
			}
		case *ast.SelectorExpr:
			if id, ok := fn.X.(*ast.Ident); ok && (id.Name == "fmt" || id.Name == "errors") {
				return nil
			}
		}
		return lc
	case *ast.BasicLit:
		lit := nn.Value
		switch nn.Kind {
		case token.STRING:
			lc.lits[Literal{lc.unquote(lit), true}] = struct{}{}
		case token.CHAR:
			lc.lits[Literal{lc.unquote(lit), false}] = struct{}{}
		case token.INT:
			if lit[0] < '0' || lit[0] > '9' {
				lc.ctxt.failf("unsupported literal '%v'", lit)
			}
			v, err := strconv.ParseInt(lit, 0, 64)
			if err != nil {
				u, err := strconv.ParseUint(lit, 0, 64)
				if err != nil {
					lc.ctxt.failf("failed to parse int literal '%v': %v", lit, err)
				}
				v = int64(u)
			}
			var val []byte
			if v >= -(1<<7) && v < 1<<8 {
				val = append(val, byte(v))
			} else if v >= -(1<<15) && v < 1<<16 {
				val = append(val, byte(v), byte(v>>8))
			} else if v >= -(1<<31) && v < 1<<32 {
				val = append(val, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
			} else {
				val = append(val, byte(v), byte(v>>8), byte(v>>16), byte(v>>24), byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
			}
			lc.lits[Literal{string(val), false}] = struct{}{}
		}
		return nil
	}
}

func trimComments(file *ast.File, fset *token.FileSet) []*ast.CommentGroup {
	var comments []*ast.CommentGroup
	for _, group := range file.Comments {
		var list []*ast.Comment
		for _, comment := range group.List {
			if strings.HasPrefix(comment.Text, "//go:") && fset.Position(comment.Slash).Column == 1 {
				list = append(list, comment)
			}
		}
		if list != nil {
			comments = append(comments, &ast.CommentGroup{List: list})
		}
	}
	return comments
}

func initialComments(content []byte) []byte {
	// Derived from go/build.Context.shouldBuild.
	end := 0
	p := content
	for len(p) > 0 {
		line := p
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line, p = line[:i], p[i+1:]
		} else {
			p = p[len(p):]
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 { // Blank line.
			end = len(content) - len(p)
			continue
		}
		if !bytes.HasPrefix(line, slashslash) { // Not comment line.
			break
		}
	}
	return content[:end]
}

type File struct {
	fset     *token.FileSet
	pkg      string
	fullName string
	astFile  *ast.File
	blocks   *[]CoverBlock
	info     *types.Info
}

var slashslash = []byte("//")

func (f *File) Visit(node ast.Node) ast.Visitor {
	switch n := node.(type) {
	case *ast.FuncDecl:
		if n.Name.String() == "init" {
			// Don't instrument init functions.
			// They run regardless of what we do, so it is just noise.
			return nil
		}
	case *ast.GenDecl:
		if n.Tok != token.VAR {
			return nil // constants and types are not interesting
		}

	case *ast.BlockStmt:
		// If it's a switch or select, the body is a list of case clauses; don't tag the block itself.
		if len(n.List) > 0 {
			switch n.List[0].(type) {
			case *ast.CaseClause: // switch
				for _, n := range n.List {
					clause := n.(*ast.CaseClause)
					clause.Body = f.addCounters(clause.Pos(), clause.End(), clause.Body, false)
				}
				return f
			case *ast.CommClause: // select
				for _, n := range n.List {
					clause := n.(*ast.CommClause)
					clause.Body = f.addCounters(clause.Pos(), clause.End(), clause.Body, false)
				}
				return f
			}
		}
		n.List = f.addCounters(n.Lbrace, n.Rbrace+1, n.List, true) // +1 to step past closing brace.
	case *ast.IfStmt:
		if n.Init != nil {
			ast.Walk(f, n.Init)
		}
		if n.Cond != nil {
			ast.Walk(f, n.Cond)
		}
		ast.Walk(f, n.Body)
		if n.Else == nil {
			// Add else because we want coverage for "not taken".
			n.Else = &ast.BlockStmt{
				Lbrace: n.Body.End(),
				Rbrace: n.Body.End(),
			}
		}
		// The elses are special, because if we have
		//	if x {
		//	} else if y {
		//	}
		// we want to cover the "if y". To do this, we need a place to drop the counter,
		// so we add a hidden block:
		//	if x {
		//	} else {
		//		if y {
		//		}
		//	}
		switch stmt := n.Else.(type) {
		case *ast.IfStmt:
			block := &ast.BlockStmt{
				Lbrace: n.Body.End(), // Start at end of the "if" block so the covered part looks like it starts at the "else".
				List:   []ast.Stmt{stmt},
				Rbrace: stmt.End(),
			}
			n.Else = block
		case *ast.BlockStmt:
			stmt.Lbrace = n.Body.End() // Start at end of the "if" block so the covered part looks like it starts at the "else".
		default:
			panic("unexpected node type in if")
		}
		ast.Walk(f, n.Else)
		return nil
	case *ast.ForStmt:
		// TODO: handle increment statement
	case *ast.SelectStmt:
		// Don't annotate an empty select - creates a syntax error.
		if n.Body == nil || len(n.Body.List) == 0 {
			return nil
		}
	case *ast.SwitchStmt:
		hasDefault := false
		if n.Body == nil {
			n.Body = new(ast.BlockStmt)
		}
		for _, s := range n.Body.List {
			if cas, ok := s.(*ast.CaseClause); ok && cas.List == nil {
				hasDefault = true
				break
			}
		}
		if !hasDefault {
			// Add default case to get additional coverage.
			n.Body.List = append(n.Body.List, &ast.CaseClause{})
		}

		// Don't annotate an empty switch - creates a syntax error.
		if n.Body == nil || len(n.Body.List) == 0 {
			return nil
		}
	case *ast.TypeSwitchStmt:
		// Don't annotate an empty type switch - creates a syntax error.
		// TODO: add default case
		if n.Body == nil || len(n.Body.List) == 0 {
			return nil
		}
	case *ast.BinaryExpr:
		if n.Op == token.LAND || n.Op == token.LOR {
			// Replace:
			//	x && y
			// with:
			//	x && func() T { return y }
			// where T is a bool of the same type as n (and x and y).

			// Spelling T correctly is a little tricky.
			// go/types gives us a canonical name for T,
			// but we can't always use that canonical name in the code directly;
			// in the general case, it is of the form a/b/c/d.U.
			// When U is the built-in bool, or defined in the current package,
			// or defined in a dot-imported package, we want just U.
			// When U is in another package, we want d.U.
			// When U is in another package, imported under the name e, we want e.U.
			// (And when the built-in bool type is shadowed, we're just screwed.)
			// Handling all of these cases correctly is hard (it requires parsing the imports),
			// so we handle just the common cases.

			// types.Default maps untyped bools to typed bools.
			typ := types.Default(f.info.Types[n].Type).String()
			// If we're in the current package, strip the package path.
			if strings.HasPrefix(typ, f.pkg+".") {
				typ = typ[len(f.pkg)+1:]
			}
			// If we're still in a package, assume it was imported with a reasonable name.
			if i := strings.LastIndexByte(typ, '/'); i >= 0 {
				typ = typ[i+1:]
			}

			n.Y = &ast.CallExpr{
				Fun: &ast.FuncLit{
					Type: &ast.FuncType{Results: &ast.FieldList{List: []*ast.Field{{Type: ast.NewIdent(typ)}}}},
					Body: &ast.BlockStmt{List: []ast.Stmt{&ast.ReturnStmt{Results: []ast.Expr{n.Y}}}},
				},
			}
		}
	}
	return f
}

func (f *File) addImport(path, name, anyIdent string) {
	newImport := &ast.ImportSpec{
		Name: ast.NewIdent(name),
		Path: &ast.BasicLit{
			Kind:  token.STRING,
			Value: fmt.Sprintf("%q", path),
		},
	}
	impDecl := &ast.GenDecl{
		Tok: token.IMPORT,
		Specs: []ast.Spec{
			newImport,
		},
	}
	// Make the new import the first Decl in the file.
	astFile := f.astFile
	astFile.Decls = append(astFile.Decls, nil)
	copy(astFile.Decls[1:], astFile.Decls[0:])
	astFile.Decls[0] = impDecl
	astFile.Imports = append(astFile.Imports, newImport)

	// Now refer to the package, just in case it ends up unused.
	// That is, append to the end of the file the declaration
	//	var _ = _cover_atomic_.AddUint32
	reference := &ast.GenDecl{
		Tok: token.VAR,
		Specs: []ast.Spec{
			&ast.ValueSpec{
				Names: []*ast.Ident{
					ast.NewIdent("_"),
				},
				Values: []ast.Expr{
					&ast.SelectorExpr{
						X:   ast.NewIdent(name),
						Sel: ast.NewIdent(anyIdent),
					},
				},
			},
		},
	}
	astFile.Decls = append(astFile.Decls, reference)
}

func (f *File) addCounters(pos, blockEnd token.Pos, list []ast.Stmt, extendToClosingBrace bool) []ast.Stmt {
	// Special case: make sure we add a counter to an empty block. Can't do this below
	// or we will add a counter to an empty statement list after, say, a return statement.
	if len(list) == 0 {
		return []ast.Stmt{f.newCounter(pos, blockEnd, 0)}
	}
	// We have a block (statement list), but it may have several basic blocks due to the
	// appearance of statements that affect the flow of control.
	var newList []ast.Stmt
	for {
		// Find first statement that affects flow of control (break, continue, if, etc.).
		// It will be the last statement of this basic block.
		var last int
		end := blockEnd
		for last = 0; last < len(list); last++ {
			end = f.statementBoundary(list[last])
			if f.endsBasicSourceBlock(list[last]) {
				extendToClosingBrace = false // Block is broken up now.
				last++
				break
			}
		}
		if extendToClosingBrace {
			end = blockEnd
		}
		if pos != end { // Can have no source to cover if e.g. blocks abut.
			newList = append(newList, f.newCounter(pos, end, last))
		}
		newList = append(newList, list[0:last]...)
		list = list[last:]
		if len(list) == 0 {
			break
		}
		pos = list[0].Pos()
	}
	return newList
}

func (f *File) endsBasicSourceBlock(s ast.Stmt) bool {
	switch s := s.(type) {
	case *ast.BlockStmt:
		// Treat blocks like basic blocks to avoid overlapping counters.
		return true
	case *ast.BranchStmt:
		return true
	case *ast.ForStmt:
		return true
	case *ast.IfStmt:
		return true
	case *ast.LabeledStmt:
		return f.endsBasicSourceBlock(s.Stmt)
	case *ast.RangeStmt:
		return true
	case *ast.SwitchStmt:
		return true
	case *ast.SelectStmt:
		return true
	case *ast.TypeSwitchStmt:
		return true
	case *ast.ExprStmt:
		// Calls to panic change the flow.
		// We really should verify that "panic" is the predefined function,
		// but without type checking we can't and the likelihood of it being
		// an actual problem is vanishingly small.
		if call, ok := s.X.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "panic" && len(call.Args) == 1 {
				return true
			}
		}
	}
	found, _ := hasFuncLiteral(s)
	return found
}

func (f *File) statementBoundary(s ast.Stmt) token.Pos {
	// Control flow statements are easy.
	switch s := s.(type) {
	case *ast.BlockStmt:
		// Treat blocks like basic blocks to avoid overlapping counters.
		return s.Lbrace
	case *ast.IfStmt:
		found, pos := hasFuncLiteral(s.Init)
		if found {
			return pos
		}
		found, pos = hasFuncLiteral(s.Cond)
		if found {
			return pos
		}
		return s.Body.Lbrace
	case *ast.ForStmt:
		found, pos := hasFuncLiteral(s.Init)
		if found {
			return pos
		}
		found, pos = hasFuncLiteral(s.Cond)
		if found {
			return pos
		}
		found, pos = hasFuncLiteral(s.Post)
		if found {
			return pos
		}
		return s.Body.Lbrace
	case *ast.LabeledStmt:
		return f.statementBoundary(s.Stmt)
	case *ast.RangeStmt:
		found, pos := hasFuncLiteral(s.X)
		if found {
			return pos
		}
		return s.Body.Lbrace
	case *ast.SwitchStmt:
		found, pos := hasFuncLiteral(s.Init)
		if found {
			return pos
		}
		found, pos = hasFuncLiteral(s.Tag)
		if found {
			return pos
		}
		return s.Body.Lbrace
	case *ast.SelectStmt:
		return s.Body.Lbrace
	case *ast.TypeSwitchStmt:
		found, pos := hasFuncLiteral(s.Init)
		if found {
			return pos
		}
		return s.Body.Lbrace
	}
	found, pos := hasFuncLiteral(s)
	if found {
		return pos
	}
	return s.End()
}

var counterGen uint32

func genCounter() int {
	counterGen++
	id := counterGen
	buf := []byte{byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24)}
	hash := sha1.Sum(buf)
	return int(uint16(hash[0]) | uint16(hash[1])<<8)
}

func (f *File) newCounter(start, end token.Pos, numStmt int) ast.Stmt {
	cnt := genCounter()

	if f.blocks != nil {
		s := f.fset.Position(start)
		e := f.fset.Position(end)
		*f.blocks = append(*f.blocks, CoverBlock{cnt, f.fullName, s.Line, s.Column, e.Line, e.Column, numStmt})
	}

	idx := &ast.BasicLit{
		Kind:  token.INT,
		Value: strconv.Itoa(cnt),
	}
	counter := &ast.IndexExpr{
		X: &ast.SelectorExpr{
			X:   ast.NewIdent(fuzzdepPkg),
			Sel: ast.NewIdent("CoverTab"),
		},
		Index: idx,
	}
	return &ast.IncDecStmt{
		X:   counter,
		Tok: token.INC,
	}
}

func (f *File) print(w io.Writer) {
	cfg := printer.Config{
		Mode:     printer.SourcePos,
		Tabwidth: 8,
		Indent:   0,
	}
	cfg.Fprint(w, f.fset, f.astFile)
}

type funcLitFinder token.Pos

func (f *funcLitFinder) Visit(node ast.Node) (w ast.Visitor) {
	if f.found() {
		return nil // Prune search.
	}
	switch n := node.(type) {
	case *ast.FuncLit:
		*f = funcLitFinder(n.Body.Lbrace)
		return nil // Prune search.
	}
	return f
}

func (f *funcLitFinder) found() bool {
	return token.Pos(*f) != token.NoPos
}

func hasFuncLiteral(n ast.Node) (bool, token.Pos) {
	if n == nil {
		return false, 0
	}
	var literal funcLitFinder
	ast.Walk(&literal, n)
	return literal.found(), token.Pos(literal)
}

func (lc *LiteralCollector) unquote(s string) string {
	t, err := strconv.Unquote(s)
	if err != nil {
		lc.ctxt.failf("cover: improperly quoted string %q\n", s)
	}
	return t
}
