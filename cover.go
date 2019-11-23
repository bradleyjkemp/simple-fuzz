// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"io"
	"math/rand"
	"strconv"
	"strings"

	"github.com/bradleyjkemp/simple-fuzz/coverage"
)

const fuzzdepPkg = "_go_fuzz_dep_"

var astPrinter = printer.Config{
	Mode:     printer.SourcePos,
	Tabwidth: 8,
	Indent:   0,
}

func instrument(fset *token.FileSet, parsedFile *ast.File, out io.Writer) {
	addCoverageImport(parsedFile)
	ast.Inspect(parsedFile, instrumentAST)

	astPrinter.Fprint(out, fset, parsedFile)
}

func instrumentAST(node ast.Node) bool {
	switch n := node.(type) {
	case *ast.IfStmt:
		// Add counter to the start of the if block
		n.Body.List = append([]ast.Stmt{newCounter()}, n.Body.List...)
		if n.Else == nil {
			// If no else block, add an empty one (will be instrumented by recursion)
			n.Else = &ast.BlockStmt{}
		}
		if e, ok := n.Else.(*ast.BlockStmt); ok {
			// If bare else statement add a counter increment
			e.List = append([]ast.Stmt{newCounter()}, e.List...)
		}
		// An else-if block is handled by recursion

	case *ast.FuncDecl:
		if n.Body == nil {
			// this is just a function declaration, it is implemented elsewhere
			return false
		}
		n.Body.List = append([]ast.Stmt{newCounter()}, n.Body.List...)

	// Single case: inside a switch statement
	case *ast.CaseClause:
		n.Body = append([]ast.Stmt{newCounter()}, n.Body...)

	// Single case: inside a select statement
	case *ast.CommClause:
		n.Body = append([]ast.Stmt{newCounter()}, n.Body...)

	case *ast.ForStmt:
		n.Body.List = append([]ast.Stmt{newCounter()}, n.Body.List...)
	}

	// Recurse deeper into the AST
	return true
}

func removeUnnecessaryComments(file *ast.File, fset *token.FileSet) {
	// Most comments get messed up when the AST is instrumented so
	// we want to remove as many comments as possible first
	n := 0
	for _, group := range file.Comments {
		for _, comment := range group.List {
			// Only keep comment groups that might affect compiler behaviour
			if strings.HasPrefix(comment.Text, "//go:") && fset.Position(comment.Slash).Column == 1 {
				file.Comments[n] = group
				n++
				break
			}
		}
	}
	file.Comments = file.Comments[:n]
}

func addCoverageImport(astFile *ast.File) {
	newImport := &ast.ImportSpec{
		Name: ast.NewIdent(fuzzdepPkg),
		Path: &ast.BasicLit{
			Kind:  token.STRING,
			Value: "\"coverage\"",
		},
	}
	impDecl := &ast.GenDecl{
		Tok: token.IMPORT,
		Specs: []ast.Spec{
			newImport,
		},
	}
	// Make the new import the first Decl in the file.
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
						X:   ast.NewIdent(fuzzdepPkg),
						Sel: ast.NewIdent("CoverTab"),
					},
				},
			},
		},
	}
	astFile.Decls = append(astFile.Decls, reference)
}

// Returns the expression:
// {
//    CoverTab[<generatedLocationID> ^ PreviousLocationID]++
//	  PreviousLocationID = <generatedLocationID> >> 1
// }
// As implemented in AFL to get pseudo path coverage
func newCounter() ast.Stmt {
	currentLocation := rand.Intn(coverage.CoverSize)

	currentID := &ast.BasicLit{
		Kind:  token.INT,
		Value: strconv.Itoa(currentLocation),
	}
	previousLocation := &ast.SelectorExpr{
		X:   ast.NewIdent(fuzzdepPkg),
		Sel: ast.NewIdent("PreviousLocationID"),
	}

	// CoverTab[currentID ^ previousLocation]
	counter := &ast.IndexExpr{
		X: &ast.SelectorExpr{
			X:   ast.NewIdent(fuzzdepPkg),
			Sel: ast.NewIdent("CoverTab"),
		},
		Index: &ast.BinaryExpr{
			X:  currentID,
			Op: token.XOR,
			Y:  previousLocation,
		},
	}

	return &ast.BlockStmt{
		List: []ast.Stmt{
			// Increment the coverage table
			&ast.IncDecStmt{
				X:   counter,
				Tok: token.INC,
			},
			// PreviousLocationID = currentLocation >> 1
			&ast.AssignStmt{
				Lhs: []ast.Expr{previousLocation},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: fmt.Sprint(currentLocation >> 1)}},
			},
		},
	}
}
