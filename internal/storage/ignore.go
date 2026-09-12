package storage

import (

	"time"  //stamping created_at

)

//IgnoreEntry is one row from the ignore list
type IgnoreEntry struct {

	Provider  string    `json:"provider"`
	Location  string    `json:"location"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`

}

//AddIgnore records (provider, location) as ignored. If it's already ignored,
//this updates reason rather than erroring. Re-running 'deadkey ignore' on the
//same slot with a new reason is expected, not a conflict
func AddIgnore(db *DB, provider, location, reason string) error {

	_, err := db.Exec(
		`INSERT INTO ignore_list (provider, location, reason, created_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(provider, location) DO UPDATE SET reason = excluded.reason`,
		provider, location, reason, time.Now().UTC().Format(time.RFC3339),
	)
	return err

}

//RemoveIgnore un-ignores a credential by location, reporting whether anything
//was actually removed. NOTE: matches on location alone, not
//'provider, location'. If two different providers ever produced the exact same
//location string, this would remove both. Considered an acceptable,
//low-probability simplification for this version rather than complicating the
//CLI's `--remove` flag with a required provider argument; worth revisiting if
//it ever causes a real collision
func RemoveIgnore(db *DB, location string) (bool, error) {

	res, err := db.Exec(`DELETE FROM ignore_list WHERE location = ?`, location)
	if err != nil {

		return false, err

	}

	n, err := res.RowsAffected()
	return n > 0, err

}

//ListIgnored returns every currently ignored credential, oldest first
func ListIgnored(db *DB) ([]IgnoreEntry, error) {

	rows, err := db.Query(`SELECT provider, location, reason, created_at FROM ignore_list ORDER BY created_at`)
	if err != nil {

		return nil, err

	}
	defer rows.Close()

	var out []IgnoreEntry
	for rows.Next() {

		var e IgnoreEntry
		var createdAt string

		if err := rows.Scan(&e.Provider, &e.Location, &e.Reason, &createdAt); err != nil {

			return nil, err

		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {

			e.CreatedAt = t

		}

		out = append(out, e)

	}

	return out, rows.Err()

}

//IsIgnored reports whether 'provider, location' is currently on the ignore list
func IsIgnored(db *DB, provider, location string) (bool, error) {

	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM ignore_list WHERE provider = ? AND location = ?`,
		provider, location,
	).Scan(&count)
	return count > 0, err

}