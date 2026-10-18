package authkit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func changelogSection(t *testing.T, version string) string {
	t.Helper()
	b, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(b), "\n## "+version+"\n")
	if !ok {
		t.Fatalf("CHANGELOG.md has no %s section", version)
	}
	sec, _, _ := strings.Cut(rest, "\n## ")
	return sec
}

func v07Section(t *testing.T) string {
	t.Helper()
	return changelogSection(t, "v0.7.0")
}

func exportedNames(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Name.IsExported() {
					names = append(names, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							names = append(names, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								names = append(names, n.Name)
							}
						}
					}
				}
			}
		}
	}
	return names
}

func TestChangelogNamesTheV07API(t *testing.T) {
	sec := v07Section(t)
	names := []string{"Recent", "RequireRecent", "Forget", "Forgotten", "Sessions", "Passkeys", "Identities", "Providers", "MoveTo",
		"ResultInviteAccepted", "ResultReverified", "ResultEmailChanged", "SourceInvite", "SourceReverify", "SourceEmailChange",
		"ReasonEmailChanged", "PurposeInvite", "PurposeEmailChange", "Reverify", "BeginReverify", "FinishReverify",
		"TicketEmail", "AuthTime", "LastAuthorize", "0007_account"}
	for _, dir := range []string{"invite", "emailchange"} {
		names = append(names, exportedNames(t, dir)...)
	}
	for _, n := range names {
		if !regexp.MustCompile("[`.]" + regexp.QuoteMeta(n) + `\b`).MatchString(sec) {
			t.Errorf("the v0.7.0 changelog does not name %s", n)
		}
	}
}

func TestChangelogNamesTheV071API(t *testing.T) {
	sec := changelogSection(t, "v0.7.1")
	for _, n := range []string{"Legacy", "Bcrypt", "SetPassword", "ListSessionsOf", "RevokeSessionOf", "AbsoluteTTLFor"} {
		if !regexp.MustCompile("[`.]" + regexp.QuoteMeta(n) + `\b`).MatchString(sec) {
			t.Errorf("the v0.7.1 changelog does not name %s", n)
		}
	}
	root := exportedNames(t, ".")
	for _, n := range []string{"ListSessionsOf", "RevokeSessionOf"} {
		if !slices.Contains(root, n) {
			t.Errorf("the root package does not export %s", n)
		}
	}
	pw := exportedNames(t, "password")
	for _, n := range []string{"Legacy", "Bcrypt", "SetPassword"} {
		if !slices.Contains(pw, n) {
			t.Errorf("package password does not export %s", n)
		}
	}
}

func TestChangelogNamesTheV080API(t *testing.T) {
	sec := changelogSection(t, "v0.8.0")
	for _, n := range []string{"RPIDs", "Origins"} {
		if !regexp.MustCompile("[`.]" + regexp.QuoteMeta(n) + `\b`).MatchString(sec) {
			t.Errorf("the v0.8.0 changelog does not name %s", n)
		}
	}
	if !strings.Contains(sec, "android:apk-key-hash:") {
		t.Errorf("the v0.8.0 changelog does not name the Android app origin form")
	}
}

func TestPackageDocs(t *testing.T) {
	for _, c := range []struct {
		dir, file, pkg string
		must           []string
	}{
		{".", "authkit.go", "authkit", []string{"ASVS 7.2.4", "ASVS 7.1.1", "is not rotated"}},
		{"invite", "doc.go", "invite", []string{"ErrSignInToAccept"}},
		{"emailchange", "doc.go", "emailchange", []string{"Rules.Change"}},
	} {
		t.Run(c.pkg, func(t *testing.T) {
			paths, err := filepath.Glob(filepath.Join(c.dir, "*.go"))
			if err != nil {
				t.Fatal(err)
			}
			var with []string
			var text string
			for _, path := range paths {
				if strings.HasSuffix(path, "_test.go") {
					continue
				}
				f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.PackageClauseOnly|parser.ParseComments)
				if err != nil {
					t.Fatal(err)
				}
				if f.Doc != nil {
					with = append(with, filepath.Base(path))
					text = strings.Join(strings.Fields(f.Doc.Text()), " ")
				}
			}
			if len(with) != 1 || with[0] != c.file {
				t.Fatalf("package %s has its doc in %v, want only %s", c.pkg, with, c.file)
			}
			if !strings.HasPrefix(text, "Package "+c.pkg+" ") {
				t.Errorf("package %s doc does not start with %q", c.pkg, "Package "+c.pkg)
			}
			for _, m := range c.must {
				if !strings.Contains(text, m) {
					t.Errorf("package %s doc does not say %q", c.pkg, m)
				}
			}
		})
	}
}
