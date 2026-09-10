package storage

import (

	"encoding/json"  //encoding providers_requested as a JSON array
	"time"  //stamping started_at/finished_at

)

//StartScan inserts a new scans row and returns its ID. Called once at the
//beginning of 'deadkey scan', before any provider runs
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

//FinishScan records when scanID completed. Called once, after every provider
//has been checked
func FinishScan(db *DB, scanID int64) error {

	_, err := db.Exec(
		`UPDATE scans SET finished_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), scanID,
	)
	return err

}