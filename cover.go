// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"crypto/sha1"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"go/types"
	"io"
	"strconv"
	"strings"
)

const fuzzdepPkg = "_go_fuzz_dep_"

func instrument(pkg, fullName string, fset *token.FileSet, parsedFile *ast.File, info *types.Info, out io.Writer) {
	file := &File{
		fset:     fset,
		pkg:      pkg,
		fullName: fullName,
		astFile:  parsedFile,
		info:     info,
	}
	file.addImport("coverage", fuzzdepPkg, "CoverTab")
	ast.Inspect(file.astFile, instrumentAST)
	file.print(out)
}

func instrumentAST(node ast.Node) bool {
	switch n := node.(type) {
	case *ast.IfStmt:
		instrumentIf(n)

	case *ast.FuncDecl:
		if n.Body == nil {
			// this is just a function declaration, it is implemented elsewhere
			return false
		}
		n.Body.List = append([]ast.Stmt{newCounter()}, n.Body.List...)
	}

	return true
}

func instrumentIf(n *ast.IfStmt) bool {
	// Add counter to the start of the if block
	n.Body.List = append([]ast.Stmt{newCounter()}, n.Body.List...)

	// Make sure else statement exists
	if n.Else == nil {
		n.Else = &ast.BlockStmt{
			List: nil,
		}
	}

	switch e := n.Else.(type) {
	case *ast.BlockStmt:
		// Add counter to else statement
		e.List = append([]ast.Stmt{newCounter()}, e.List...)
		return true
	case *ast.IfStmt:
		// Recurse to cover the else-if
		return instrumentIf(e)
	default:
		panic("unexpected else type")
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

type File struct {
	fset     *token.FileSet
	pkg      string
	fullName string
	astFile  *ast.File
	info     *types.Info
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

var counterGen uint32

func genCounter() int {
	counterGen++
	id := counterGen
	buf := []byte{byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24)}
	hash := sha1.Sum(buf)
	return int(uint16(hash[0]) | uint16(hash[1])<<8)
}

func newCounter() ast.Stmt {
	cnt := genCounter()

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
