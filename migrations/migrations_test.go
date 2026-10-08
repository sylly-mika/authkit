package migrations_test

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sylly-mika/authkit/migrations"
)

func TestAllIsContiguousAndComplete(t *testing.T) {
	all := migrations.All()
	if len(all) == 0 {
		t.Fatal("no migrations embedded")
	}
	for i, m := range all {
		if m.ID != i+1 || m.Name == "" || strings.TrimSpace(m.Up) == "" || strings.TrimSpace(m.Down) == "" {
			t.Errorf("migration %d = {%d %q up:%d down:%d}, want ID %d with a name, an up and a down", i, m.ID, m.Name, len(m.Up), len(m.Down), i+1)
		}
	}
	if migrations.Version != all[len(all)-1].ID {
		t.Fatalf("Version = %d, want the last migration's ID %d", migrations.Version, all[len(all)-1].ID)
	}
}

func TestAllRefusesTwoNamesUnderOneID(t *testing.T) {
	fsys := fstest.MapFS{
		"0001_a.up.sql":   {Data: []byte("SELECT 1;")},
		"0001_b.down.sql": {Data: []byte("SELECT 1;")},
	}
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "0001 is both a and b") {
			t.Fatalf("0001_a.up and 0001_b.down = panic %v, want 0001 is both a and b", r)
		}
	}()
	migrations.Load(fsys)
}

// TestEveryUpBumpsAuthSchema: CheckSchema compares auth_schema.version with
// the last migration's ID, so each up writes exactly its own ID, once, and each
// later down puts back the ID before it (0001's down drops the table).
func TestEveryUpBumpsAuthSchema(t *testing.T) {
	writes := regexp.MustCompile(`(?i)(?:INSERT\s+INTO|UPDATE)\s+auth_schema\b[^;]*;`)
	for _, m := range migrations.All() {
		up, down := []string{fmt.Sprintf("UPDATE auth_schema SET version = %d;", m.ID)}, []string{fmt.Sprintf("UPDATE auth_schema SET version = %d;", m.ID-1)}
		if m.ID == 1 {
			up, down = []string{fmt.Sprintf("INSERT INTO auth_schema (id, version) VALUES (true, %d);", m.ID)}, nil
		}
		if got := writes.FindAllString(m.Up, -1); !slices.Equal(got, up) {
			t.Errorf("%04d_%s.up.sql writes auth_schema as %q, want exactly %q (spec §5.3)", m.ID, m.Name, got, up)
		}
		if got := writes.FindAllString(m.Down, -1); !slices.Equal(got, down) {
			t.Errorf("%04d_%s.down.sql writes auth_schema as %q, want exactly %q (spec §5.3)", m.ID, m.Name, got, down)
		}
	}
}

func TestRenderReplacesEveryPlaceholder(t *testing.T) {
	for _, m := range migrations.All() {
		for _, sql := range []string{m.Up, m.Down} {
			out, err := migrations.Render(sql, "users")
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if strings.Contains(out, "{{") {
				t.Errorf("%04d_%s left a placeholder: %s", m.ID, m.Name, out)
			}
		}
	}
	core, _ := migrations.Render(migrations.All()[0].Up, "users")
	if strings.Count(core, "REFERENCES users (id)") != 3 {
		t.Fatalf("0001_core references users %d times, want 3 (credentials, sessions, events)", strings.Count(core, "REFERENCES users (id)"))
	}
}

func TestRenderRefusesABadIdentifier(t *testing.T) {
	for _, bad := range []string{"", "Users", "users; DROP TABLE x", "1users", `"users"`, strings.Repeat("u", 64)} {
		if _, err := migrations.Render("{{principals}}", bad); err == nil {
			t.Errorf("Render accepted %q", bad)
		}
	}
}
