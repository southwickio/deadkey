package storage

import (

	"database/sql"  //for sql.ErrNoRows
	"encoding/json"  //encoding/decoding providers_requested and providers_failed
	"errors"  //for errors.Is
	"time"  //stamping/parsing started_at/finished_at

	"github.com/southwickio/deadkey/internal/models"

)

//Scan is one persisted scan run's own record - separate from the
//per-credential AssessmentRow rows it owns. This is what internal/dashboard
//reads to render a past scan's header (when it ran, which providers were
//checked, which failed outright)
type Scan struct {

	ID                 int64
	StartedAt          time.Time
	FinishedAt         time.Time //zero value if the scan never finished cleanly
	ProvidersRequested []string
	ProvidersFailed    []models.ProviderFailure
	CIMode             bool

}

//StartScan inserts a new scans row and returns its ID. Called once at the
//beginning of `deadkey scan`, before any provider runs
func StartScan(db *DB, providersRequested []string, ciMode bool) (int64, error) {

	requested, err := json.Marshal(providersRequested)
	if err != nil {

		return 0, err

	}

	res, err := db.Exec(
		`INSERT INTO scans (started_at, providers_requested, ci_mode) VALUES (?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), string(requested), ciMode,
	)
	if err != nil {

		return 0, err

	}

	return res.LastInsertId()

}

//FinishScan records when scanID completed and which providers (if any)
//failed outright during it. Called once, after every provider has been
//checked
//
//providersFailed is persisted here - not just returned in-memory to
//cmd/deadkey/scan.go's Report for that one run - specifically so
//internal/dashboard can show it when browsing a PAST scan later. This is
//exactly the kind of schema change the PRAGMA user_version migration system
//(see migrations.go) was built to support safely: providers_failed did not
//exist in the original schema and was added in migration version 2
func FinishScan(db *DB, scanID int64, providersFailed []models.ProviderFailure) error {

	failed, err := json.Marshal(providersFailed)
	if err != nil {

		return err

	}

	_, err = db.Exec(
		`UPDATE scans SET finished_at = ?, providers_failed = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), string(failed), scanID,
	)
	return err

}

//LatestScanID returns the most recently STARTED scan's ID. Returns
//(0, false, nil) if no scan has ever run - the caller (internal/dashboard)
//treats that as the empty-state case, not an error
func LatestScanID(db *DB) (int64, bool, error) {

	var id int64
	err := db.QueryRow(`SELECT id FROM scans ORDER BY id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {

		return 0, false, nil

	}
	if err != nil {

		return 0, false, err

	}

	return id, true, nil

}

//GetScan reads a single scan's own record by ID. Returns (Scan{}, false, nil)
//if scanID doesn't exist, mirroring LatestScanID's not-found convention
//rather than a bare sql.ErrNoRows leaking out to callers
func GetScan(db *DB, scanID int64) (Scan, bool, error) {

	var (
		s                  Scan
		startedAt          string
		finishedAt         sql.NullString
		requestedJSON      string
		failedJSON         sql.NullString
		ciMode             int
	)

	err := db.QueryRow(
		`SELECT id, started_at, finished_at, providers_requested, providers_failed, ci_mode
		 FROM scans WHERE id = ?`, scanID,
	).Scan(&s.ID, &startedAt, &finishedAt, &requestedJSON, &failedJSON, &ciMode)

	if errors.Is(err, sql.ErrNoRows) {

		return Scan{}, false, nil

	}
	if err != nil {

		return Scan{}, false, err

	}

	if t, parseErr := time.Parse(time.RFC3339, startedAt); parseErr == nil {

		s.StartedAt = t

	}
	if finishedAt.Valid {

		if t, parseErr := time.Parse(time.RFC3339, finishedAt.String); parseErr == nil {

			s.FinishedAt = t

		}

	}

	if err := json.Unmarshal([]byte(requestedJSON), &s.ProvidersRequested); err != nil {

		return Scan{}, false, err

	}
	if failedJSON.Valid && failedJSON.String != "" {

		//A decode failure here is deliberately non-fatal - providers_failed
		//is supplementary detail (which providers had trouble), not
		//something that should sink an entire scan's page from rendering
		_ = json.Unmarshal([]byte(failedJSON.String), &s.ProvidersFailed)

	}

	s.CIMode = ciMode != 0

	return s, true, nil

}

//ListRecentScans returns up to limit scans, most recent first. Used by
//internal/dashboard to render a simple scan-history navigation list -
//exposing history that has been recorded since the very first storage
//cycle (every scan writes new rows, never overwrites previous ones) but
//had no reader for it anywhere until the dashboard needed one
func ListRecentScans(db *DB, limit int) ([]Scan, error) {

	rows, err := db.Query(
		`SELECT id, started_at, finished_at, providers_requested, providers_failed, ci_mode
		 FROM scans ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {

		return nil, err

	}
	defer rows.Close()

	var out []Scan
	for rows.Next() {

		var (
			s             Scan
			startedAt     string
			finishedAt    sql.NullString
			requestedJSON string
			failedJSON    sql.NullString
			ciMode        int
		)

		if err := rows.Scan(&s.ID, &startedAt, &finishedAt, &requestedJSON, &failedJSON, &ciMode); err != nil {

			return nil, err

		}

		if t, parseErr := time.Parse(time.RFC3339, startedAt); parseErr == nil {

			s.StartedAt = t

		}
		if finishedAt.Valid {

			if t, parseErr := time.Parse(time.RFC3339, finishedAt.String); parseErr == nil {

				s.FinishedAt = t

			}

		}
		_ = json.Unmarshal([]byte(requestedJSON), &s.ProvidersRequested)
		if failedJSON.Valid && failedJSON.String != "" {

			_ = json.Unmarshal([]byte(failedJSON.String), &s.ProvidersFailed)

		}
		s.CIMode = ciMode != 0

		out = append(out, s)

	}

	return out, rows.Err()

}
