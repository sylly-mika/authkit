package nsql

import (
	"fmt"
	"regexp"
	"strings"
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
