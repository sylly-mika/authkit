// Command authkit-gen copies authkit's migrations into an app's golang-migrate
// or goose directory, numbered after the app's own (spec §5.3, P3 spec §3.4):
//
//	go run github.com/sylly-mika/authkit/cmd/authkit-gen -principals users -out migrations
//	go run github.com/sylly-mika/authkit/cmd/authkit-gen -format goose -principals administrators -out migrations
//
// authkit.lock (in the working directory by default) records what it wrote;
// a second run writes only migrations a newer library added. Run the app's
// own hash and order checks afterwards (ino-tasks: make migrate-hash, make migrate-check).
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	principals := flag.String("principals", "", "the app's user table (required)")
	out := flag.String("out", "migrations", "the app's golang-migrate directory")
	lock := flag.String("lock", "authkit.lock", "the lock file recording what was generated")
	format := flag.String("format", formatMigrate, "the app's migration format: golang-migrate or goose")
	flag.Parse()
	if *principals == "" {
		fmt.Fprintln(os.Stderr, "usage: authkit-gen -principals <table> [-out migrations] [-lock authkit.lock] [-format golang-migrate|goose]")
		os.Exit(2)
	}
	written, err := run(options{principals: *principals, out: *out, lock: *lock, format: *format, version: libraryVersion()})
	for _, f := range written {
		fmt.Println(f)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(written) == 0 {
		fmt.Println("authkit-gen: up to date")
	}
}
