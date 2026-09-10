//Package storage is deadkey's local SQLite persistence layer: scan history,
//credential identity across scans, and the ignore list. See migrations.go
//for the schema itself and its versioning strategy
package storage

import (

	"database/sql"  //Go's generic SQL interface, used with the driver below
	"fmt"  //building error messages
	"path/filepath"  //building the database file path

	_ "modernc.org/sqlite"  //registers the sqlite driver, used via database/sql

)

//DB wraps a single, long-lived *sql.DB connection pool for deadkey's local
//database. Callers should Open() exactly once per process and Close() once at
//exit; never open/close per operation. Repeatedly reopening a WAL-mode SQLite
//connection can require brief exclusive locks during connect/disconnect, which
//is unnecessary overhead and a real, if rare, source of spurious "database is
//locked" errors this project has no reason to accept
type DB struct {

	*sql.DB

}

//Open opens (creating if necessary) the SQLite database at dir/data.db,
//applies the PRAGMAs this project depends on, and runs any pending schema
//migrations (see migrations.go)
//
//PRAGMA choices, each a deliberate decision:
//  - journal_mode=WAL: lets `deadkey serve` read while `deadkey scan` is
//    mid-write, without either blocking the other
//  - busy_timeout=5000: if a write momentarily can't acquire the lock (two
//    scans overlapping), wait up to 5 seconds rather than failing immediately.
//  - synchronous=NORMAL: the standard, safe pairing with WAL mode; full
//    durability against an application crash, a negligibly small window of
//    vulnerability only on a full OS crash/power loss, an acceptable
//    tradeoff for a local credential-scan history, not a financial ledger
//  - foreign_keys=1: SQLite does not enforce foreign key constraints unless
//    explicitly told to; this project's schema relies on them
//
//modernc.org/sqlite (a pure-Go, CGO-free SQLite implementation) is used over
//the more common mattn/go-sqlite3, because this project's own distribution plan
//is exactly the scenario CGO is documented to complicate. mattn's driver
//requires a working C toolchain for every target platform being cross-compiled
//to
func Open(dir string) (*DB, error) {

	path := filepath.Join(dir, "data.db")
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)",
		path,
	)

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {

		return nil, fmt.Errorf("storage: opening %s: %w", path, err)

	}

	if err := sqlDB.Ping(); err != nil {

		sqlDB.Close()
		return nil, fmt.Errorf("storage: connecting to %s: %w", path, err)

	}

	db := &DB{sqlDB}

	if err := migrate(db); err != nil {

		sqlDB.Close()
		return nil, fmt.Errorf("storage: migrating %s: %w", path, err)

	}

	return db, nil

}