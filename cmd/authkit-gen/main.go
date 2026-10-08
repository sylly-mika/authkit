// Command authkit-gen copies authkit's migrations into an app's golang-migrate
// directory, numbered after the app's own (spec §5.3):
//
//	go run github.com/sylly-mika/authkit/cmd/authkit-gen -principals users -out migrations
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
	flag.Parse()
	if *principals == "" {
		fmt.Fprintln(os.Stderr, "usage: authkit-gen -principals <table> [-out migrations] [-lock authkit.lock]")
		os.Exit(2)
	}
	written, err := run(options{principals: *principals, out: *out, lock: *lock, version: libraryVersion()})
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
