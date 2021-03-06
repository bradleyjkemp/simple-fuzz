// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
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

func instrumentFile(parsedFile *ast.File) {
	addCoverageImport(parsedFile)
	ast.Inspect(parsedFile, func(node ast.Node) bool {
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
			// Add a declaration of:
			//   PreviousLocationID := 0
			// And a counter
			n.Body.List = append([]ast.Stmt{newLastLocation(), newCounter()}, n.Body.List...)
		case *ast.FuncLit:
			// Add a declaration of:
			//   PreviousLocationID := 0
			// And a counter
			n.Body.List = append([]ast.Stmt{newLastLocation(), newCounter()}, n.Body.List...)

		case *ast.SwitchStmt:
			hasDefault := false
			for _, c := range n.Body.List {
				if len(c.(*ast.CaseClause).List) == 0 {
					// This switch already has a default clause
					hasDefault = true
					break
				}
			}
			if !hasDefault {
				// this switch doesn't have a default clause so add an empty one
				n.Body.List = append(n.Body.List, &ast.CaseClause{
					List: nil,
					Body: []ast.Stmt{},
				})
			}

		// Single case: inside a switch statement
		case *ast.CaseClause:
			n.Body = append([]ast.Stmt{newCounter()}, n.Body...)

		// Single case: inside a select statement
		case *ast.CommClause:
			n.Body = append([]ast.Stmt{newCounter()}, n.Body...)

		case *ast.ForStmt:
			n.Body.List = append([]ast.Stmt{newCounter()}, n.Body.List...)
		case *ast.RangeStmt:
			n.Body.List = append([]ast.Stmt{newCounter()}, n.Body.List...)
		}

		// Recurse deeper into the AST
		return true
	})
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
			Value: "\"github.com/bradleyjkemp/simple-fuzz/coverage\"",
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

func newLastLocation() ast.Stmt {
	return &ast.DeclStmt{Decl: &ast.GenDecl{
		Tok: token.VAR,
		Specs: []ast.Spec{
			&ast.ValueSpec{
				Names: []*ast.Ident{
					ast.NewIdent("PreviousLocationID"),
				},
				Values: []ast.Expr{
					&ast.BasicLit{
						Kind:  token.INT,
						Value: "0",
					},
				},
				Comment: nil,
			},
		},
	}}
}

// Returns the expression:
// {
//    CoverTab[<generatedLocationID> ^ PreviousLocationID]++
//	  PreviousLocationID = <generatedLocationID> >> 1
// }
// As implemented in AFL to get pseudo path coverage.
// PreviousLocationID is a function-local variable (as global variables
// cause noise with goroutines)
func newCounter() ast.Stmt {
	currentLocation := rand.Intn(coverage.CoverSize)

	currentID := &ast.BasicLit{
		Kind:  token.INT,
		Value: strconv.Itoa(currentLocation),
	}
	previousLocation := ast.NewIdent("PreviousLocationID")

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
			// Set the entry in coverage table
			&ast.AssignStmt{
				Lhs: []ast.Expr{counter},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BasicLit{Value: "1", Kind: token.INT}},
			},
			//// Increment the coverage table
			//&ast.IncDecStmt{
			//	X:   counter,
			//	Tok: token.INC,
			//},
			// PreviousLocationID = currentLocation >> 1
			&ast.AssignStmt{
				Lhs: []ast.Expr{previousLocation},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: fmt.Sprint(currentLocation >> 1)}},
			},
		},
	}
}
