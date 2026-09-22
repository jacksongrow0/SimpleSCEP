package database

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// go-jet's row mapper fails silently. When a column alias does not match a
// field on the scan destination, nothing errors: the query runs, the SQL is
// correct, and the mapper hands back a zero-valued struct — or an empty slice —
// with a nil error. Every symptom then points at the WHERE clause or at row
// level security, so the search happens in the wrong place entirely.
//
// The rule that decides it, measured against qrm v2.15.0 (getTypeName /
// typeToColumnIndex): for a *named* destination type the mapper looks each
// field up as "<TypeName>.<FieldName>", lowercased with _, - and spaces
// stripped. So:
//
//   - a named destination needs every alias prefixed — .AS("Event.ID");
//   - an alias to an anonymous struct (type row = struct{...}) has an empty
//     type name, so it needs bare aliases — .AS("ID");
//   - a generated model.X works with unaliased table columns, since jet emits
//     "login_challenge.id" and the type name supplies "loginchallenge".
//
// These tests read the source rather than executing queries, and that is the
// point: reproducing the bug at runtime needs a database with a row in the
// right table, which is exactly the condition a unit suite does not have.
// qrm.GlobalConfig.StrictScan turns the silence into a panic and is worth
// enabling wherever fixtures exist, but it only runs once a row has been
// scanned, so on an empty table it proves nothing.

type jetSource struct {
	fset *token.FileSet
	// fields maps pkg.Type to its normalised field names.
	fields map[string]map[string]string
	// embeds maps pkg.Type to the embedded type names it carries.
	embeds map[string][]string
	// kind maps pkg.Type to "defined", "alias" or "".
	kind map[string]string
	// helpers maps pkg.funcName to the aliases in a statement-building helper.
	helpers map[string][]alias
	// dests holds every scan destination found.
	dests []dest
}

type alias struct {
	value string
	pos   string
}

type dest struct {
	pkg, typ, fn, pos string
	aliases           []alias
	helpers           []string
}

func loadJetSource(t *testing.T) *jetSource {
	t.Helper()
	s := &jetSource{
		fset:    token.NewFileSet(),
		fields:  map[string]map[string]string{},
		embeds:  map[string][]string{},
		kind:    map[string]string{},
		helpers: map[string][]alias{},
	}
	root := filepath.Join("..", "..", "internal")
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	sort.Strings(files)
	if len(files) < 20 {
		t.Fatalf("found only %d source files; the scan is broken and every check "+
			"below would pass vacuously", len(files))
	}

	parsed := map[string]*ast.File{}
	for _, p := range files {
		f, err := parser.ParseFile(s.fset, p, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", p, err)
		}
		parsed[p] = f
		pkg := filepath.Base(filepath.Dir(p))
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts := spec.(*ast.TypeSpec)
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				key := pkg + "." + ts.Name.Name
				if ts.Assign.IsValid() {
					s.kind[key] = "alias"
				} else {
					s.kind[key] = "defined"
				}
				s.fields[key] = map[string]string{}
				for _, fl := range st.Fields.List {
					if len(fl.Names) == 0 {
						s.embeds[key] = append(s.embeds[key], typeName(fl.Type))
						continue
					}
					for _, nm := range fl.Names {
						s.fields[key][normalise(nm.Name)] = nm.Name
					}
				}
			}
		}
	}

	for _, p := range files {
		pkg := filepath.Base(filepath.Dir(p))
		for _, decl := range parsed[p].Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			aliases, helpers, destinations := s.inspect(fn)
			if returnsStatement(fn) {
				s.helpers[pkg+"."+fn.Name.Name] = aliases
			}
			for _, d := range destinations {
				s.dests = append(s.dests, dest{
					pkg: pkg, typ: d, fn: fn.Name.Name,
					pos:     p + ":" + strconv.Itoa(s.fset.Position(fn.Pos()).Line),
					aliases: aliases, helpers: helpers,
				})
			}
		}
	}
	return s
}

// inspect pulls the column aliases, the statement helpers called, and the scan
// destinations out of one function body.
func (s *jetSource) inspect(fn *ast.FuncDecl) (aliases []alias, helpers []string, dests []string) {
	locals := map[string]string{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.ValueSpec:
			if v.Type != nil {
				for _, nm := range v.Names {
					locals[nm.Name] = typeName(v.Type)
				}
			}
		case *ast.Ident:
			// A statement helper carries its aliases in its own body. It is
			// matched on the identifier rather than on the call shape because
			// callers reach it as helper().WHERE(...), where the helper is the
			// receiver's own call expression and never a plain selector.
			if strings.HasSuffix(v.Name, "Statement") && v.Name != "RawStatement" {
				helpers = append(helpers, v.Name)
			}
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "AS":
				// A table alias — table.Foo.AS("c") — names a relation, not a
				// column, and must be left alone.
				if len(v.Args) == 1 && !isTableExpr(sel.X) {
					if lit, ok := v.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						val, _ := strconv.Unquote(lit.Value)
						aliases = append(aliases, alias{value: val,
							pos: s.fset.Position(lit.Pos()).String()})
					}
				}
			case "QueryContext":
				if len(v.Args) == 0 {
					return true
				}
				un, ok := v.Args[len(v.Args)-1].(*ast.UnaryExpr)
				if !ok {
					return true
				}
				if t, ok := locals[typeName(un.X)]; ok {
					dests = append(dests, t)
				}
			}
		}
		return true
	})
	return aliases, helpers, dests
}

// TestJetNamedDestinationsUsePrefixedAliases is the check that would have caught
// every instance of this: a defined struct read with bare aliases maps nothing.
func TestJetNamedDestinationsUsePrefixedAliases(t *testing.T) {
	s := loadJetSource(t)
	checked := 0
	for _, d := range s.dests {
		typ := strings.TrimPrefix(strings.TrimPrefix(d.typ, "[]"), "*")
		if strings.HasPrefix(typ, "model.") || strings.HasPrefix(typ, "struct{") {
			continue
		}
		key := typ
		if !strings.Contains(key, ".") {
			key = d.pkg + "." + key
		}
		kind := s.kind[key]
		if kind == "" {
			continue
		}
		aliases := d.aliases
		for _, h := range d.helpers {
			aliases = append(aliases, s.helpers[d.pkg+"."+h]...)
		}
		if len(aliases) == 0 {
			continue
		}
		checked++
		want := typ[strings.LastIndex(typ, ".")+1:] + "."
		for _, a := range aliases {
			switch kind {
			case "defined":
				if !strings.HasPrefix(a.value, want) {
					t.Errorf("%s scans into %s, a defined struct, but aliases a column %q.\n"+
						"go-jet resolves its fields as %q, so this column maps to nothing and the "+
						"whole row comes back zero-valued with a nil error (%s)",
						d.pos+" "+d.fn, key, a.value, want+"…", a.pos)
				}
			case "alias":
				if strings.Contains(a.value, ".") {
					t.Errorf("%s scans into %s, an alias to an anonymous struct, but aliases a "+
						"column %q. An anonymous type has no name to match, so the prefix makes "+
						"this column map to nothing (%s)", d.pos+" "+d.fn, key, a.value, a.pos)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("checked no scan destinations; the scan is broken")
	}
	t.Logf("checked %d aliased scan destinations", checked)
}

// TestJetAliasesNameRealFields catches the other half. A prefix on a misspelled
// field is just as silent as no prefix at all — that column simply never lands.
func TestJetAliasesNameRealFields(t *testing.T) {
	s := loadJetSource(t)
	for _, d := range s.dests {
		aliases := d.aliases
		for _, h := range d.helpers {
			aliases = append(aliases, s.helpers[d.pkg+"."+h]...)
		}
		for _, a := range aliases {
			typ, field, ok := strings.Cut(a.value, ".")
			if !ok {
				continue
			}
			key := d.pkg + "." + typ
			if s.fields[key] == nil {
				continue
			}
			if _, ok := s.fields[key][normalise(field)]; !ok {
				t.Errorf("%s aliases a column %q, but %s has no field %q. "+
					"That column maps to nothing and the field stays zero (%s)",
					d.pos+" "+d.fn, a.value, key, field, a.pos)
			}
		}
	}
}

// TestJetDestinationsDoNotEmbed records the trap that no alias can fix.
//
// go-jet does not flatten an embedded struct into its parent: it reads it as a
// nested relation to populate, finds no columns addressed to it, and leaves the
// embedded value entirely zero while filling the parent's own fields and
// returning a nil error. pki.Revocation embedded pki.Certificate and every
// revoked certificate came back with an empty serial — neither
// "Revocation.Serial" nor "Certificate.Serial" reaches it; both were measured.
// Scan flat into an anonymous row and assemble in Go instead.
func TestJetDestinationsDoNotEmbed(t *testing.T) {
	s := loadJetSource(t)
	for _, d := range s.dests {
		typ := strings.TrimPrefix(strings.TrimPrefix(d.typ, "[]"), "*")
		if strings.HasPrefix(typ, "model.") || strings.HasPrefix(typ, "struct{") {
			continue
		}
		key := typ
		if !strings.Contains(key, ".") {
			key = d.pkg + "." + key
		}
		if embedded := s.embeds[key]; len(embedded) > 0 {
			t.Errorf("%s scans into %s, which embeds %s. go-jet treats an embedded "+
				"struct as a relation rather than flattening it, so those fields stay "+
				"zero however the columns are aliased. Scan flat and convert in Go",
				d.pos+" "+d.fn, key, strings.Join(embedded, ", "))
		}
	}
}

// normalise matches qrm's own key normalisation.
func normalise(s string) string {
	s = strings.ToLower(s)
	for _, c := range []string{"_", "-", " "} {
		s = strings.ReplaceAll(s, c, "")
	}
	return s
}

// isTableExpr reports whether e is table.Foo, the receiver of a relation alias.
func isTableExpr(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "table"
}

func returnsStatement(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, r := range fn.Type.Results.List {
		if strings.HasSuffix(typeName(r.Type), "SelectStatement") {
			return true
		}
	}
	return false
}

func typeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return typeName(v.X) + "." + v.Sel.Name
	case *ast.ArrayType:
		return "[]" + typeName(v.Elt)
	case *ast.StarExpr:
		return "*" + typeName(v.X)
	case *ast.StructType:
		return "struct{...}"
	}
	return ""
}
