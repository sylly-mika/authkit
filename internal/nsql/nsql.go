package nsql

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/sylly-mika/authkit/db"
)

var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

var tables = regexp.MustCompile(`\bauth_(schema|sessions|tokens|events|throttle|credentials|passkeys|passkey_ceremonies|second_factors|recovery_codes|second_step_challenges|email_codes|ceremonies|identities)\b`)

// Check reports whether schema can name an install's PostgreSQL schema.
func Check(schema string) error {
	if !schemaName.MatchString(schema) {
		return fmt.Errorf("authkit: schema %q is not a lower-case identifier of at most 63 bytes", schema)
	}
	if schema == "public" || schema == "information_schema" || strings.HasPrefix(schema, "pg_") {
		return fmt.Errorf("authkit: schema %q is reserved by PostgreSQL", schema)
	}
	return nil
}

// Rewrite qualifies every authkit table name in sql with schema; an empty schema returns sql unchanged.
func Rewrite(schema, sql string) string {
	if schema == "" {
		return sql
	}
	var b strings.Builder
	for i := 0; i < len(sql); {
		end := i
		switch {
		case sql[i] == '\'':
			end = len(sql)
			if j := strings.IndexByte(sql[i+1:], '\''); j >= 0 {
				end = i + 1 + j + 1
			}
			b.WriteString(sql[i:end])
		case strings.HasPrefix(sql[i:], "--"):
			end = len(sql)
			if j := strings.IndexByte(sql[i:], '\n'); j >= 0 {
				end = i + j
			}
			b.WriteString(sql[i:end])
		default:
			for end < len(sql) && sql[end] != '\'' && !strings.HasPrefix(sql[end:], "--") {
				end++
			}
			b.WriteString(qualify(schema, sql[i:end]))
		}
		i = end
	}
	return b.String()
}

func qualify(schema, span string) string {
	var b strings.Builder
	last := 0
	for _, m := range tables.FindAllStringIndex(span, -1) {
		if m[0] > 0 && span[m[0]-1] == '.' {
			continue
		}
		b.WriteString(span[last:m[0]])
		b.WriteString(schema + ".")
		b.WriteString(span[m[0]:m[1]])
		last = m[1]
	}
	b.WriteString(span[last:])
	return b.String()
}

// Names qualifies authkit's table names in every statement run through a querier from Q.
type Names struct {
	schema string
	cache  sync.Map
}

// NewNames returns the Names for schema; "" leaves statements unchanged.
func NewNames(schema string) *Names { return &Names{schema: schema} }

// Q returns q with its statements qualified; q itself when n is nil, the schema is empty or q is nil.
func (n *Names) Q(q db.Querier) db.Querier {
	if n == nil || n.schema == "" || q == nil {
		return q
	}
	if w, ok := q.(querier); ok && w.n == n {
		return q
	}
	return querier{n: n, q: Plain(q)}
}

// Plain returns the querier behind every Names wrapper around q.
func Plain(q db.Querier) db.Querier {
	for {
		w, ok := q.(querier)
		if !ok {
			return q
		}
		q = w.q
	}
}

// WHY: only the library's own statements pass through a Names (Principals and OnEvent get Plain), so the cache is bounded.
func (n *Names) sql(query string) string {
	if v, ok := n.cache.Load(query); ok {
		return v.(string)
	}
	out := Rewrite(n.schema, query)
	n.cache.Store(query, out)
	return out
}

type querier struct {
	n *Names
	q db.Querier
}

func (w querier) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	return w.q.Exec(ctx, w.n.sql(query), args...)
}
func (w querier) Query(ctx context.Context, query string, args ...any) (db.Rows, error) {
	return w.q.Query(ctx, w.n.sql(query), args...)
}
func (w querier) QueryRow(ctx context.Context, query string, args ...any) db.Row {
	return w.q.QueryRow(ctx, w.n.sql(query), args...)
}
func (w querier) InTx() bool         { return w.q.InTx() }
func (w querier) Unwrap() db.Querier { return w.q }
