package storage

import (

	"fmt"  //building error messages

)

//currentSchemaVersion is bumped every time a migration is appended below. Never
//reused or renumbered. Each version's migration is permanent history
const currentSchemaVersion = 1

//migration is one ordered step from version-1 to version. Its statements run
//inside a single transaction, so a failure partway through leaves the
//database at its previous, consistent version rather than half-migrated
type migration struct {

	version    int
	statements []string

}

//migrations is the complete, ordered history of this database's schema.
//Appending a new migration here is the only sanctioned way to change the schema
//after this version ships. This is what makes "the schema can safely change
//later" an actual designed-for property of this project, not something deferred
//to a future crisis
var migrations = []migration{

	{

		version: 1,
		statements: []string{

			`CREATE TABLE scans (
				id                   INTEGER PRIMARY KEY,
				started_at           TEXT NOT NULL,
				finished_at          TEXT,
				providers_requested  TEXT NOT NULL,
				ci_mode              INTEGER NOT NULL DEFAULT 0
			)`,

			//UNIQUE(provider, location) is the "logical/slot-based identity".
			//Identity survives credential rotation, since a new value in the
			//same slot is still the same row. identifier is an optional
			//secondary key (see models.Credential.Identifier) that lets
			//identity also survive a changed location when a provider supplies
			//a safe non-secret identifier. Not every provider does, see
			//credentials.go
			`CREATE TABLE credentials (
				id             INTEGER PRIMARY KEY,
				provider       TEXT NOT NULL,
				subtype        TEXT NOT NULL,
				location       TEXT NOT NULL,
				identifier     TEXT,
				first_seen_at  TEXT NOT NULL,
				last_seen_at   TEXT NOT NULL,
				UNIQUE(provider, location)
			)`,

			`CREATE INDEX idx_credentials_provider_identifier
				ON credentials(provider, identifier)
				WHERE identifier IS NOT NULL`,

			//One row per credential per scan, never updated after insert. This
			//is what lets history/trends exist later without a schema change,
			//per assessment.go's design principle that evidence layers are
			//never overwritten
			`CREATE TABLE assessments (
				id                            INTEGER PRIMARY KEY,
				scan_id                       INTEGER NOT NULL REFERENCES scans(id),
				credential_id                 INTEGER NOT NULL REFERENCES credentials(id),
				discovery_confidence          TEXT NOT NULL,
				validation_status             TEXT NOT NULL,
				validation_checked_at         TEXT,
				validation_error_detail       TEXT,
				validation_checked_endpoint   TEXT,
				activity_last_used_at         TEXT,
				activity_quality              TEXT,
				activity_source               TEXT,
				risk_tier                     TEXT,
				risk_score                    INTEGER,
				risk_reasoning                TEXT,
				risk_modifiers                TEXT,
				ignored                       INTEGER NOT NULL DEFAULT 0
			)`,

			`CREATE INDEX idx_assessments_scan ON assessments(scan_id)`,
			`CREATE INDEX idx_assessments_credential ON assessments(credential_id)`,

			`CREATE TABLE ignore_list (
				provider    TEXT NOT NULL,
				location    TEXT NOT NULL,
				reason      TEXT,
				created_at  TEXT NOT NULL,
				PRIMARY KEY (provider, location)
			)`,

		},

	},

	{

		//Added when internal/dashboard needed to show which providers failed
		//outright on a PAST scan, not just the one currently running.
		//cmd/deadkey/scan.go already computed this in-memory for its own
		//Report, but never persisted it
		version: 2,
		statements: []string{

			`ALTER TABLE scans ADD COLUMN providers_failed TEXT`,

		},

	},

}

//migrate brings db up to currentSchemaVersion, applying any migrations it
//hasn't seen yet, in order. Refuses to proceed (rather than guessing) if the
//database's stored version is ahead of what this build knows about: the case
//where someone downgraded deadkey after a newer version already wrote to this
//file
func migrate(db *DB) error {

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {

		return fmt.Errorf("reading schema version: %w", err)

	}

	if version > currentSchemaVersion {

		return fmt.Errorf(
			"this database was created by a newer version of deadkey (schema version %d, this build supports up to %d) - upgrade deadkey before using this database again",
			version, currentSchemaVersion,
		)

	}

	for _, m := range migrations {

		if m.version <= version {

			continue

		}

		if err := applyMigration(db, m); err != nil {

			return fmt.Errorf("applying migration %d: %w", m.version, err)

		}

	}

	return nil

}

func applyMigration(db *DB, m migration) error {

	tx, err := db.Begin()
	if err != nil {

		return err

	}
	defer tx.Rollback() //no-op once committed

	for _, stmt := range m.statements {

		if _, err := tx.Exec(stmt); err != nil {

			return fmt.Errorf("statement failed: %w\n%s", err, stmt)

		}

	}

	//PRAGMA statements don't reliably accept ? bind parameters across SQLite
	//drivers, so this is built with Sprintf. Safe here: m.version is an
	//internal int from this file's own migrations slice, never user input
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {

		return fmt.Errorf("updating schema version: %w", err)

	}

	return tx.Commit()

}