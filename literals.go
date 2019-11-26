package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"

	"golang.org/x/tools/go/packages"
)

func (c *Context) gatherLiterals(targets []*packages.Package, isIgnored func(string) bool) []string {
	nolits := map[string]bool{
		"math":    true,
		"os":      true,
		"unicode": true,
	}

	lits := make(map[string]struct{})
	visit := func(pkg *packages.Package) {
		if isIgnored(pkg.PkgPath) || nolits[pkg.PkgPath] {
			return
		}
		for _, f := range pkg.Syntax {
			ast.Walk(&LiteralCollector{lits: lits, ctxt: c}, f)
		}
	}

	packages.Visit(targets, nil, visit)

	litsList := make([]string, 0, len(lits))
	for lit, _ := range lits {
		litsList = append(litsList, lit)
	}
	return litsList
}

type LiteralCollector struct {
	ctxt *Context
	lits map[string]struct{}
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
		case token.CHAR:
			// Conver 'a' -> "a"
			lit = strconv.Quote(fmt.Sprintf("%c", lit[1]))
			fallthrough
		case token.STRING:
			lc.lits[lit] = struct{}{}
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
			lc.lits[strconv.Quote(string(val))] = struct{}{}
		}
		return nil
	}
}
