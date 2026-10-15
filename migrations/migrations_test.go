package migrations_test

import (
	"crypto/sha256"
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

// TestGooseWrapsOnlyDollarQuotedStatements is spec §3.4: goose splits an
// unannotated section at semicolons, so a $$ body is wrapped whole.
func TestGooseWrapsOnlyDollarQuotedStatements(t *testing.T) {
	up := "-- a comment\nCREATE TABLE t (a int);\n\nCREATE FUNCTION f() RETURNS trigger AS $$\nBEGIN\n    NEW.a := 1;\n    RETURN NEW;\nEND;\n$$ LANGUAGE plpgsql;\nUPDATE auth_schema SET version = 9;\n"
	down := "DROP FUNCTION f();\nDROP TABLE t;\n"
	want := "-- +goose Up\n-- a comment\nCREATE TABLE t (a int);\n\n-- +goose StatementBegin\nCREATE FUNCTION f() RETURNS trigger AS $$\nBEGIN\n    NEW.a := 1;\n    RETURN NEW;\nEND;\n$$ LANGUAGE plpgsql;\n-- +goose StatementEnd\nUPDATE auth_schema SET version = 9;\n" +
		"\n-- +goose Down\nDROP FUNCTION f();\nDROP TABLE t;\n"
	if got := migrations.Goose(up, down); got != want {
		t.Fatalf("Goose =\n%s\nwant\n%s", got, want)
	}
	for _, m := range migrations.All() {
		if strings.Contains(migrations.Goose(m.Up, m.Down), "StatementBegin") {
			t.Errorf("%04d_%s holds no $$, yet Goose wrapped a statement", m.ID, m.Name)
		}
	}
}

func TestRenderInWithoutASchemaKeepsTheBytes(t *testing.T) {
	hashes := []struct{ up, down string }{
		{"ab9b3b2f6ad6c518b319f6993428f25996cda2c1c53d08f5634ab37f2216280d", "f178e138ec9c265803ce8e1242f15457da8d4eb7dc42674dd243e3dcc44756fc"},
		{"0f61986ffb9cbb39d8056141de54c64f4daf86e4550403db43b1fa19964c1b5e", "7efa200f4caae25fcfdf3536e44e807bdeae3a530e6d1a6a42a9fb55958e5ac9"},
		{"61e3763bd06f552ae7677873f48c5ebdbd01e7414324d4c4fffe5d432327e3ac", "619a15413852904fbbd4d3cacb961e8df843d3183ee3576c94550b382db0d348"},
		{"2f6f0b1898562c1533ce322e267c32aef87db054bc8bec8f12aad7218247548a", "26ff7d19dfea7e662c7700641a7ef8e5c02996e138a120afb5ba47dc928ca59c"},
	}
	all := migrations.All()
	for i, h := range hashes {
		m := all[i]
		if m.ID != i+1 {
			t.Fatalf("All()[%d] is ID %d, want %d", i, m.ID, i+1)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(m.Up))); got != h.up {
			t.Errorf("%04d_%s up hashes to %s, want %s", m.ID, m.Name, got, h.up)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(m.Down))); got != h.down {
			t.Errorf("%04d_%s down hashes to %s, want %s", m.ID, m.Name, got, h.down)
		}
	}
	for _, m := range all {
		for _, sql := range []string{m.Up, m.Down} {
			want, err := migrations.Render(sql, "users")
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			got, err := migrations.RenderIn(sql, "users", "")
			if err != nil {
				t.Fatalf("RenderIn with no schema: %v", err)
			}
			if got != want {
				t.Errorf("%04d_%s: RenderIn with no schema differs from Render", m.ID, m.Name)
			}
		}
	}
}

func TestRenderInQualifiesEveryTableName(t *testing.T) {
	const schema = "kit_ns"
	counts := []struct{ id, up, down int }{{1, 14, 6}, {2, 2, 2}, {3, 11, 7}, {4, 9, 7}}
	all := migrations.All()
	for _, c := range counts {
		m := all[c.id-1]
		for _, p := range []struct {
			name, sql string
			want      int
		}{{"up", m.Up, c.up}, {"down", m.Down, c.down}} {
			out, err := migrations.RenderIn(p.sql, "users", schema)
			if err != nil {
				t.Fatalf("%04d_%s %s: %v", m.ID, m.Name, p.name, err)
			}
			if got := strings.Count(out, "kit_ns.auth_"); got != p.want {
				t.Errorf("%04d_%s %s has %d kit_ns.auth_ names, want %d", m.ID, m.Name, p.name, got, p.want)
			}
			if strings.Contains(out, "{{") {
				t.Errorf("%04d_%s %s left a placeholder", m.ID, m.Name, p.name)
			}
		}
	}
	core, err := migrations.RenderIn(all[0].Up, "users", schema)
	if err != nil {
		t.Fatalf("render 0001 up: %v", err)
	}
	if !strings.Contains(core, "REFERENCES users (id)") {
		t.Errorf("0001_core up lost its unqualified principals reference")
	}
	if !strings.Contains(core, "CREATE TABLE kit_ns.auth_schema (") {
		t.Errorf("0001_core up does not create kit_ns.auth_schema")
	}
}

func TestRenderInRefusesABadSchema(t *testing.T) {
	for _, c := range []struct{ schema, want string }{
		{"public", `authkit: schema "public" is reserved by PostgreSQL`},
		{"Kit", `authkit: schema "Kit" is not a lower-case identifier of at most 63 bytes`},
	} {
		out, err := migrations.RenderIn(migrations.All()[0].Up, "users", c.schema)
		if out != "" {
			t.Errorf("RenderIn with schema %q returned SQL", c.schema)
		}
		if err == nil || err.Error() != c.want {
			t.Errorf("RenderIn with schema %q: error %v, want %q", c.schema, err, c.want)
		}
	}
}
