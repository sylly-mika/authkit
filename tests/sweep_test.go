package tests

import (
	"context"
	"errors"
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/onetime"
)

type counted struct {
	db.Querier
	n *int
}

func (c counted) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	*c.n++
	return c.Querier.Exec(ctx, query, args...)
}

func (c counted) Query(ctx context.Context, query string, args ...any) (db.Rows, error) {
	*c.n++
	return c.Querier.Query(ctx, query, args...)
}

func (c counted) QueryRow(ctx context.Context, query string, args ...any) db.Row {
	*c.n++
	return c.Querier.QueryRow(ctx, query, args...)
}

var (
	sweptReads = []string{"Authenticate", "ListSessions", "ListEvents", "ListPasskeys", "HasCredential", "SecondFactorStatus", "OneTime.CreatedSince", "OneTime.Peek"}
	sweptPure  = []string{"Codec", "OneTime", "ResetFloor", "CheckPassword", "AcquireHashSlot", "Attach"}
)

func TestWriteMethodsRefuseABareConnection(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	res := w.SignIn("ada@example.invalid", "the right password")
	var n int
	c, q := w.Claims(res), counted{Querier: sqldb.Conn(w.Pinned(id)), n: &n}
	p, links, ctx := authkit.Principal{ID: id, Login: "ada@example.invalid"}, w.Svc.OneTime(), w.Ctx
	calls := map[string]func() error{
		"Login": func() error {
			_, err := w.Svc.Password.Login(ctx, q, "staff", p.Login, "x", authkit.Meta{})
			return err
		},
		"Refresh": func() error {
			_, err := w.Svc.Refresh(ctx, q, "staff", res.Tokens.RefreshToken, authkit.Meta{})
			return err
		},
		"Logout": func() error { _, err := w.Svc.Logout(ctx, q, c, authkit.Meta{}); return err },
		"ChangePassword": func() error {
			_, err := w.Svc.Password.ChangePassword(ctx, q, c, "the right password", "another password", authkit.Meta{})
			return err
		},
		"RevokeSession": func() error { _, err := w.Svc.RevokeSession(ctx, q, c, res.Session.ID, authkit.Meta{}); return err },
		"RequestReset":  func() error { _, err := w.Svc.Password.RequestReset(ctx, q, "staff", p.Login); return err },
		"CompleteReset": func() error {
			_, err := w.Svc.Password.CompleteReset(ctx, q, "staff", "x", "another password", authkit.Meta{})
			return err
		},
		"SetPassword": func() error {
			_, err := w.Svc.Password.SetPassword(ctx, q, p, "staff", "another password", authkit.Meta{})
			return err
		},
		"VerifyPassword": func() error {
			_, err := w.Svc.Password.VerifyPassword(ctx, q, p, "staff", "x", authkit.Meta{})
			return err
		},
		"OpenSession": func() error { _, err := w.Svc.OpenSession(ctx, q, p, "staff", authkit.Meta{}); return err },
		"VerifySecondStep": func() error {
			_, err := w.Svc.VerifySecondStep(ctx, q, "staff", "x", authkit.FactorTOTP, "123456", authkit.Meta{})
			return err
		},
		"SendSecondStepEmail": func() error {
			_, err := w.Svc.SendSecondStepEmail(ctx, q, "staff", "x", authkit.Meta{})
			return err
		},
		"BeginPasskeyLogin": func() error { _, err := w.Svc.BeginPasskeyLogin(ctx, q, "staff", authkit.Meta{}); return err },
		"FinishPasskeyLogin": func() error {
			_, err := w.Svc.FinishPasskeyLogin(ctx, q, "staff", "x", []byte("{}"), authkit.Meta{})
			return err
		},
		"BeginPasskeyRegistration": func() error { _, err := w.Svc.BeginPasskeyRegistration(ctx, q, c, authkit.Meta{}); return err },
		"FinishPasskeyRegistration": func() error {
			_, err := w.Svc.FinishPasskeyRegistration(ctx, q, c, "x", []byte("{}"), "", authkit.Meta{})
			return err
		},
		"RenamePasskey":           func() error { _, err := w.Svc.RenamePasskey(ctx, q, c, uuid.New(), "x"); return err },
		"DeletePasskey":           func() error { _, err := w.Svc.DeletePasskey(ctx, q, c, uuid.New(), authkit.Meta{}); return err },
		"BeginTOTPSetup":          func() error { _, err := w.Svc.BeginTOTPSetup(ctx, q, c, authkit.Meta{}); return err },
		"ConfirmTOTP":             func() error { _, err := w.Svc.ConfirmTOTP(ctx, q, c, "000000", authkit.Meta{}); return err },
		"RegenerateRecoveryCodes": func() error { _, err := w.Svc.RegenerateRecoveryCodes(ctx, q, c, authkit.Meta{}); return err },
		"BeginEmailCodeSetup":     func() error { _, err := w.Svc.BeginEmailCodeSetup(ctx, q, c, authkit.Meta{}); return err },
		"ConfirmEmailCode": func() error {
			_, err := w.Svc.ConfirmEmailCode(ctx, q, c, "x", authkit.Meta{})
			return err
		},
		"RequestEmailProof": func() error { _, err := w.Svc.RequestEmailProof(ctx, q, c, authkit.Meta{}); return err },
		"DisableSecondFactor": func() error {
			_, err := w.Svc.DisableSecondFactor(ctx, q, c, authkit.FactorTOTP, authkit.FactorProof{}, authkit.Meta{})
			return err
		},
		"MintEmailCode": func() error { _, err := w.Svc.MintEmailCode(ctx, q, uuid.New()); return err },
		"OpenSessionFrom": func() error {
			_, err := w.Svc.OpenSessionFrom(ctx, q, res.Session.ID, p, "staff", authkit.Meta{})
			return err
		},
		"RevokeAllSessions": func() error {
			_, err := w.Svc.RevokeAllSessions(ctx, q, id, authkit.ReasonAdmin, authkit.Meta{})
			return err
		},
		"AuthenticateSession": func() error {
			_, err := w.Svc.AuthenticateSession(ctx, q, "staff", res.Tokens.RefreshToken, authkit.Meta{})
			return err
		},
		"Prune":          func() error { return w.Svc.Prune(ctx, q) },
		"OneTime.Lock":   func() error { return links.Lock(ctx, q, "reset", id) },
		"OneTime.Create": func() error { _, err := links.Create(ctx, q, "reset", id, time.Hour); return err },
		"OneTime.Mint":   func() error { _, err := links.Mint(ctx, q, uuid.New()); return err },
		"OneTime.Spend":  func() error { _, err := links.Spend(ctx, q, "x", "reset"); return err },
		"OneTime.Revoke": func() error { return links.Revoke(ctx, q, "reset", id) },
		"OneTime.Prune":  func() error { _, err := links.Prune(ctx, q, time.Now()); return err },
	}
	for name, call := range calls {
		n = 0
		if err := call(); !errors.Is(err, db.ErrTxRequired) {
			t.Errorf("%s on a bare connection = %v, want db.ErrTxRequired", name, err)
		}
		if n != 0 {
			t.Errorf("%s ran %d statements on a bare connection before refusing it", name, n)
		}
	}
	for prefix, typ := range map[string]reflect.Type{"": reflect.TypeFor[*authkit.Service](), "OneTime.": reflect.TypeFor[*onetime.Store]()} {
		for i := range typ.NumMethod() {
			name := prefix + typ.Method(i).Name
			if _, swept := calls[name]; !swept && !slices.Contains(sweptReads, name) && !slices.Contains(sweptPure, name) {
				t.Errorf("%s is neither in the bare-connection sweep nor listed as a read or a pure method", name)
			}
		}
	}
}

func TestReadMethodsAcceptABarePinnedConnection(t *testing.T) {
	w := newWorld(t, withPasskeys, withSecondFactors)
	id := w.User("ada@example.invalid", "the right password")
	res := w.SignIn("ada@example.invalid", "the right password")
	pk := w.addStoredPasskey(id, "Laptop", false)
	bob := w.User("bob@example.invalid", "x")
	w.addStoredPasskey(bob, "Bob key", false)
	w.D.Exec(w.T, "INSERT INTO auth_second_factors (principal_id, kind, secret, last_step, created_at, confirmed_at) VALUES ($1, 'totp', $2, NULL, $3, $3)", id, []byte{1}, w.Clock.Now())
	w.seedRecoveryCodes(id, 2)
	w.D.Exec(w.T, "INSERT INTO auth_second_factors (principal_id, kind, secret, last_step, created_at, confirmed_at) VALUES ($1, 'email', NULL, NULL, $2, $2)", bob, w.Clock.Now())
	w.seedRecoveryCodes(bob, 5)
	q, c := sqldb.Conn(w.Pinned(id)), w.Claims(res)
	if got, err := w.Svc.Authenticate(w.Ctx, q, c); err != nil || got.Refusal != nil {
		t.Errorf("Authenticate = %v, %v", got.Refusal, err)
	}
	if _, total, err := w.Svc.ListSessions(w.Ctx, q, c, 10, 0); err != nil || total != 1 {
		t.Errorf("ListSessions = %d, %v", total, err)
	}
	if _, total, err := w.Svc.ListEvents(w.Ctx, q, id, nil, 10, 0); err != nil || total != 1 {
		t.Errorf("ListEvents = %d, %v", total, err)
	}
	if has, err := w.Svc.Password.HasCredential(w.Ctx, q, id); err != nil || !has {
		t.Errorf("HasCredential = %v, %v", has, err)
	}
	if list, err := w.Svc.ListPasskeys(w.Ctx, q, id); err != nil || len(list) != 1 || list[0].ID != pk {
		t.Errorf("ListPasskeys = %d passkeys, %v, want the one passkey %s", len(list), err, pk)
	}
	if status, err := w.Svc.SecondFactorStatus(w.Ctx, q, c); err != nil || status != (authkit.FactorStatus{TOTP: true, RecoveryCodesLeft: 2}) {
		t.Errorf("SecondFactorStatus = %+v, %v, want the TOTP factor on with 2 recovery codes", status, err)
	}
}

var (
	insertReturning = regexp.MustCompile(`(?is)\bINSERT\s+INTO\b[^;]*?\bRETURNING\b`)
	dbClock         = regexp.MustCompile(`(?i)\b(now|clock_timestamp|statement_timestamp|transaction_timestamp|timeofday)\s*\(|\b(current_timestamp|current_date|current_time|localtimestamp|localtime)\b|'(now|today|tomorrow|yesterday)'`)
)

type literal struct {
	pos  token.Position
	text string
}

func literals(path string, src []byte) []literal {
	fset := token.NewFileSet()
	var s scanner.Scanner
	s.Init(fset.AddFile(path, -1, len(src)), src, nil, 0)
	var out []literal
	var cur *literal
	operand := false
	for {
		pos, tok, lit := s.Scan()
		switch {
		case tok == token.STRING:
			text, err := strconv.Unquote(lit)
			if err != nil {
				text = lit
			}
			if cur != nil && operand {
				cur.text += text
			} else {
				out = append(out, literal{pos: fset.Position(pos), text: text})
				cur = &out[len(out)-1]
			}
			operand = false
		case tok == token.ADD && cur != nil && !operand:
			operand = true
		case tok == token.IDENT && cur != nil && operand:
			cur.text += "?"
			operand = false
		default:
			cur, operand = nil, false
		}
		if tok == token.EOF {
			return out
		}
	}
}

func sqlViolations(re *regexp.Regexp, path string, src []byte) []string {
	var out []string
	for _, l := range literals(path, src) {
		if m := re.FindString(l.text); m != "" {
			out = append(out, l.pos.String()+" "+strconv.Quote(m))
		}
	}
	return out
}

func librarySources(t *testing.T, fn func(path string, src []byte, migration bool)) {
	t.Helper()
	// WHY: go test runs in tests/, so the library root is the parent directory.
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("..", path)
		if err != nil {
			return err
		}
		slash := filepath.ToSlash(rel)
		if d.IsDir() {
			if slash == "cmd" || slash == "docs" {
				return filepath.SkipDir
			}
			return nil
		}
		isGo := strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
		isMigration := strings.HasSuffix(path, ".sql") && strings.HasPrefix(slash, "migrations/")
		if !isGo && !isMigration {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fn(path, src, isMigration)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// WHY: under a self-insert-only policy an INSERT with RETURNING needs a row the writer may not read, so ids come from rand.
func TestNoInsertUsesReturning(t *testing.T) {
	librarySources(t, func(path string, src []byte, migration bool) {
		if migration {
			return
		}
		for _, v := range sqlViolations(insertReturning, path, src) {
			t.Errorf("%s has an INSERT … RETURNING (spec §5)", v)
		}
	})
}

func TestNoSQLReadsTheDatabaseClock(t *testing.T) {
	librarySources(t, func(path string, src []byte, migration bool) {
		if !migration {
			for _, v := range sqlViolations(dbClock, path, src) {
				t.Errorf("%s reads the database clock; pass the injected clock's now (P3)", v)
			}
			return
		}
		for i, line := range strings.Split(string(src), "\n") {
			line, _, _ = strings.Cut(line, "--")
			if m := dbClock.FindString(line); m != "" {
				t.Errorf("%s:%d reads the database clock (%q); pass the injected clock's now (P3)", path, i+1, m)
			}
		}
	})
}

func TestTheSweepPatternsCatchPlantedViolations(t *testing.T) {
	for re, cases := range map[*regexp.Regexp]struct{ caught, clean []string }{
		dbClock: {
			caught: []string{
				"package p\nvar q = `SELECT now()`\n",
				"package p\nvar q = \"SELECT now()\"\n",
				"package p\nvar q = `UPDATE t SET at = ` + \"CURRENT_TIMESTAMP\"\n",
				"package p\nvar q = `SELECT 1 FROM t WHERE at < localtimestamp`\n",
				"package p\nvar q = `SELECT 1 FROM t WHERE at < 'now'::timestamptz`\n",
				"package p\nvar q = `SELECT 1 FROM t WHERE d = current_date`\n",
				"package p\nvar q = `SELECT clock_timestamp()`\n",
			},
			clean: []string{
				"package p\nfunc (s *S) now() time.Time { return s.c.Now() }\n",
				"package p\n// now() in a comment\nvar q = `SELECT 1 FROM t WHERE at < $1`\n",
				"package p\nvar q = `SELECT ` + columns + ` FROM t WHERE known_at < $1`\n",
			},
		},
		insertReturning: {
			caught: []string{
				"package p\nvar q = `INSERT INTO t (a) VALUES ($1) RETURNING id`\n",
				"package p\nvar q = \"insert into t (a) values ($1) returning id\"\n",
				"package p\nvar q = `INSERT INTO t (a) VALUES ($1)` + ` RETURNING id`\n",
				"package p\nvar q = `INSERT INTO t (` + cols + `) VALUES ($1)\n RETURNING id`\n",
			},
			clean: []string{
				"package p\nvar q = `UPDATE t SET a = $1 RETURNING id`\n",
				"package p\nvar a, b = `INSERT INTO t (a) VALUES ($1)`, `SELECT id FROM t RETURNING`\n",
			},
		},
	} {
		for _, src := range cases.caught {
			if sqlViolations(re, "planted.go", []byte(src)) == nil {
				t.Errorf("%s missed %q", re, src)
			}
		}
		for _, src := range cases.clean {
			if v := sqlViolations(re, "planted.go", []byte(src)); v != nil {
				t.Errorf("%s flagged clean %q: %v", re, src, v)
			}
		}
	}
}
