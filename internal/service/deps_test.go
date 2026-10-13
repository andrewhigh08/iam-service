package service

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// modulePrefix is the import path prefix of this module.
const modulePrefix = "github.com/andrewhigh08/iam-service/"

// TestLayering keeps the service layer free of adapter imports and limits its module-internal
// dependencies to domain, port and internal/pkg.
func TestLayering(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquote import %s: %v", name, imp.Path.Value, err)
			}
			if strings.Contains(path, "/internal/adapter/") {
				t.Errorf("%s imports adapter package %s", name, path)
			}
			if !strings.HasSuffix(name, "_test.go") && strings.HasPrefix(path, modulePrefix) && !allowedInternalImport(path) {
				t.Errorf("%s imports %s; the service layer may import only domain, port and internal/pkg", name, path)
			}
		}
	}
}

// allowedInternalImport reports whether a module-internal import path is open to the service layer.
func allowedInternalImport(path string) bool {
	rel := strings.TrimPrefix(path, modulePrefix)
	return rel == "internal/domain" || rel == "internal/port" || strings.HasPrefix(rel, "internal/pkg/")
}
