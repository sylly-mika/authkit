package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	"github.com/sylly-mika/authkit/migrations"
)

const module = "github.com/sylly-mika/authkit"

// The migration formats: golang-migrate's up and down pair, or one goose file.
const (
	formatMigrate = "golang-migrate"
	formatGoose   = "goose"
)

type options struct {
	principals string
	out        string
	lock       string
	format     string // "" is golang-migrate
	version    string
	library    []migrations.Migration // nil is migrations.All()
}

// lockFile records what the generator wrote into an app (spec §5.3). A lock
// without a format is golang-migrate's, as v0.1 wrote it.
type lockFile struct {
	Library    string      `json:"library"`
	Principals string      `json:"principals"`
	Format     string      `json:"format"`
	Migrations []lockEntry `json:"migrations"`
}

type lockEntry struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"` // of the rendered up and down, without the header
}

var (
	appMigration   = regexp.MustCompile(`^(\d+)_.+\.(up|down)\.sql$`)
	gooseMigration = regexp.MustCompile(`^(\d+)_.+\.(sql|go)$`)
)

// reserved is pg_get_keywords() catcode R or T on PostgreSQL 17.10: neither parses as a table name.
var reserved = []string{
	"all", "analyse", "analyze", "and", "any", "array", "as", "asc", "asymmetric", "authorization",
	"binary", "both", "case", "cast", "check", "collate", "collation", "column", "concurrently",
	"constraint", "create", "cross", "current_catalog", "current_date", "current_role",
	"current_schema", "current_time", "current_timestamp", "current_user", "default", "deferrable",
	"desc", "distinct", "do", "else", "end", "except", "false", "fetch", "for", "foreign",
	"freeze", "from", "full", "grant", "group", "having", "ilike", "in", "initially", "inner",
	"intersect", "into", "is", "isnull", "join", "lateral", "leading", "left", "like", "limit",
	"localtime", "localtimestamp", "natural", "not", "notnull", "null", "offset", "on", "only",
	"or", "order", "outer", "overlaps", "placing", "primary", "references", "returning", "right",
	"select", "session_user", "similar", "some", "symmetric", "system_user", "table",
	"tablesample", "then", "to", "trailing", "true", "union", "unique", "user", "using",
	"variadic", "verbose", "when", "where", "window", "with",
}

// checkPrincipals refuses a name the rendered SQL cannot use unquoted, and one
// in authkit's or PostgreSQL's own namespace.
func checkPrincipals(name string) error {
	switch {
	case slices.Contains(reserved, name):
		return fmt.Errorf("authkit-gen: %q is a PostgreSQL reserved word, not a usable principals table name", name)
	case strings.HasPrefix(name, "auth_"), strings.HasPrefix(name, "pg_"):
		return fmt.Errorf("authkit-gen: %q is in authkit's or PostgreSQL's namespace (auth_*, pg_*), not a usable principals table name", name)
	}
	if _, err := migrations.Render("", name); err != nil {
		return fmt.Errorf("authkit-gen: %q is not a lower-case table name", name)
	}
	return nil
}

// run writes every library migration the lock does not list into o.out, in
// o.format, numbered after the highest migration already there, and rewrites
// the lock. It refuses, before any write, a lock it could not write, a lock
// of another format, a locked migration whose rendering changed and an
// unlocked one o.out already holds. It never overwrites a file. It returns
// the files it wrote.
func run(o options) ([]string, error) {
	if err := checkPrincipals(o.principals); err != nil {
		return nil, err
	}
	if o.format == "" {
		o.format = formatMigrate
	}
	if o.format != formatMigrate && o.format != formatGoose {
		return nil, fmt.Errorf("authkit-gen: -format %q is neither %s nor %s", o.format, formatMigrate, formatGoose)
	}
	library := o.library
	if library == nil {
		library = migrations.All()
	}
	lock, err := readLock(o.lock)
	if err != nil {
		return nil, err
	}
	if lock.Principals != "" && lock.Principals != o.principals {
		return nil, fmt.Errorf("authkit-gen: %s was generated for principals table %q, not %q", o.lock, lock.Principals, o.principals)
	}
	if lock.Format == "" {
		lock.Format = formatMigrate
	}
	if len(lock.Migrations) > 0 && lock.Format != o.format {
		return nil, fmt.Errorf("authkit-gen: %s was generated as %s, not %s: an app keeps one migration format", o.lock, lock.Format, o.format)
	}
	if _, err := os.Stat(filepath.Dir(o.lock)); err != nil {
		return nil, fmt.Errorf("authkit-gen: the lock's directory: %w", err)
	}
	locked := map[int]lockEntry{}
	for _, e := range lock.Migrations {
		locked[e.ID] = e
	}
	next, width, err := nextNumber(o.out, o.format)
	if err != nil {
		return nil, err
	}
	type rendered struct {
		m             migrations.Migration
		up, down, sum string
	}
	var todo []rendered
	for _, m := range library {
		r := rendered{m: m}
		if r.up, err = migrations.Render(m.Up, o.principals); err != nil {
			return nil, err
		}
		if r.down, err = migrations.Render(m.Down, o.principals); err != nil {
			return nil, err
		}
		r.sum = fmt.Sprintf("%x", sha256.Sum256([]byte(r.up+"\x00"+r.down)))
		if e, ok := locked[m.ID]; ok {
			if e.SHA256 != r.sum {
				return nil, fmt.Errorf("authkit-gen: library migration %04d_%s no longer renders what %s holds: ship the change as a new library migration (delete %s and its lock entry only if no database ever applied it)", m.ID, m.Name, e.File, e.File)
			}
			continue
		}
		if dup, _ := filepath.Glob(filepath.Join(o.out, "*_authkit_"+m.Name+".*")); len(dup) > 0 {
			return nil, fmt.Errorf("authkit-gen: %s already holds %s, which %s does not list: restore the lock instead of generating a second copy", o.out, filepath.Base(dup[0]), o.lock)
		}
		todo = append(todo, r)
	}
	var written []string
	for _, r := range todo {
		base := fmt.Sprintf("%0*d_authkit_%s", width, next, r.m.Name)
		parts := []struct{ suffix, sql string }{{".up.sql", r.up}, {".down.sql", r.down}}
		if o.format == formatGoose {
			parts = []struct{ suffix, sql string }{{".sql", migrations.Goose(r.up, r.down)}}
		}
		for _, part := range parts {
			path := filepath.Join(o.out, base+part.suffix)
			if err := writeNew(path, header(o.version, r.m)+part.sql); err != nil {
				return written, err
			}
			written = append(written, path)
		}
		lock.Migrations = append(lock.Migrations, lockEntry{ID: r.m.ID, Name: r.m.Name, File: base, SHA256: r.sum})
		next++
	}
	lock.Library, lock.Principals, lock.Format = o.version, o.principals, o.format
	return written, writeLock(o.lock, lock)
}

func header(version string, m migrations.Migration) string {
	return fmt.Sprintf("-- Generated by authkit-gen from %s %s, migration %04d_%s.\n"+
		"-- Applied migration files are immutable: never edit this file; a new library migration arrives as a new file.\n\n",
		module, version, m.ID, m.Name)
}

// nextNumber is one above the highest migration in dir and the digit width
// the app uses: NNN_*.up|down.sql for golang-migrate (6 digits when there is
// none), NNN_*.sql or .go for goose (5, goose's own padding).
func nextNumber(dir, format string) (next, width int, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, fmt.Errorf("authkit-gen: read %s: %w", dir, err)
	}
	pattern, width := appMigration, 6
	if format == formatGoose {
		pattern, width = gooseMigration, 5
	}
	for _, e := range entries {
		m := pattern.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, 0, err
		}
		if n >= next {
			next, width = n, len(m[1])
		}
	}
	return next + 1, width, nil
}

func writeNew(path, body string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("authkit-gen: %w", err)
	}
	if _, err := f.WriteString(body); err != nil {
		f.Close()
		return fmt.Errorf("authkit-gen: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("authkit-gen: %w", err)
	}
	return nil
}

func readLock(path string) (lockFile, error) {
	var l lockFile
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return l, fmt.Errorf("authkit-gen: %w", err)
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return l, fmt.Errorf("authkit-gen: %s: %w", path, err)
	}
	return l, nil
}

func writeLock(path string, l lockFile) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return fmt.Errorf("authkit-gen: %w", err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("authkit-gen: %w", err)
	}
	return nil
}

// libraryVersion is the authkit version this binary was built from: the
// dependency's version when an app runs it, the main module's in this repo.
func libraryVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(unknown)"
	}
	if info.Main.Path == module {
		return info.Main.Version
	}
	for _, d := range info.Deps {
		if d.Path == module {
			return d.Version
		}
	}
	return "(devel)"
}
