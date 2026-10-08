// Package migrations is authkit's schema as embedded SQL. Each file is written
// once with a {{principals}} placeholder for the app's user table;
// cmd/authkit-gen renders them into the app's migrations directory.
//
// A new migration takes the next ID, NNNN_name.{up,down}.sql. Its up writes
// auth_schema once, as `UPDATE auth_schema SET version = NNNN;`, and its down
// puts back the ID before it (TestEveryUpBumpsAuthSchema); CheckSchema compares
// the version with the last ID. A released file never changes: apps hold it,
// applied, under their own number.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
)

//go:embed *.sql
var files embed.FS

const placeholder = "{{principals}}"

// Migration is one library migration; ID is the schema version it brings.
type Migration struct {
	ID   int
	Name string
	Up   string
	Down string
}

var (
	fileName   = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.(up|down)\.sql$`)
	identifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
)

// All is every library migration in order. The files are embedded at build
// time, so a malformed name is a build defect and panics.
func All() []Migration { return load(files) }

func load(fsys fs.FS) []Migration {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		panic(err)
	}
	byID := map[int]*Migration{}
	for _, e := range entries {
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil {
			panic(fmt.Sprintf("migrations: %s is not NNNN_name.up|down.sql", e.Name()))
		}
		id, _ := strconv.Atoi(m[1])
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			panic(err)
		}
		mig := byID[id]
		if mig != nil && mig.Name != m[2] {
			panic(fmt.Sprintf("migrations: %04d is both %s and %s", id, mig.Name, m[2]))
		}
		if mig == nil {
			mig = &Migration{ID: id, Name: m[2]}
			byID[id] = mig
		}
		if m[3] == "up" {
			mig.Up = string(body)
		} else {
			mig.Down = string(body)
		}
	}
	out := make([]Migration, 0, len(byID))
	for id := 1; id <= len(byID); id++ {
		mig, ok := byID[id]
		if !ok {
			panic(fmt.Sprintf("migrations: %04d is missing", id))
		}
		out = append(out, *mig)
	}
	return out
}

// Version is the schema version this library needs: the last migration's ID.
var Version = func() int { all := All(); return all[len(all)-1].ID }()

// Render substitutes the app's principals table into one migration file.
func Render(sql, principals string) (string, error) {
	if !identifier.MatchString(principals) {
		return "", fmt.Errorf("authkit: %q is not a lower-case table name", principals)
	}
	return strings.ReplaceAll(sql, placeholder, principals), nil
}
