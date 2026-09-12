package storage

import (

	"database/sql"  //for sql.ErrNoRows
	"errors"  //for errors.Is
	"time"  //stamping first_seen_at/last_seen_at

	"github.com/southwickio/deadkey/internal/models"

)

//UpsertCredential records cred's identity, returning its stable database ID.
//Matching prefers cred.Identifier when the provider supplied one (a safe,
//non-secret identifier. See models.Credential's doc comment), falling back to
//(provider, location) otherwise. This means a credential found under a
//different Location string across scans (for example: moved from one env var to
//another) is still recognized as the same credential when an Identifier is
//available. Not yet populated by every provider. A real, documented partial
//improvement, not a universal fix.
//
//Never overwrites first_seen_at. Always refreshes last_seen_at
func UpsertCredential(db *DB, cred models.Credential) (int64, error) {

	now := time.Now().UTC().Format(time.RFC3339)

	if cred.Identifier != "" {

		var id int64
		err := db.QueryRow(
			`SELECT id FROM credentials WHERE provider = ? AND identifier = ?`,
			cred.Provider, cred.Identifier,
		).Scan(&id)

		if err == nil {

			_, err = db.Exec(
				`UPDATE credentials SET last_seen_at = ?, location = ?, subtype = ? WHERE id = ?`,
				now, cred.Location, string(cred.Subtype), id,
			)
			return id, err

		}
		if !errors.Is(err, sql.ErrNoRows) {

			return 0, err

		}

	}

	var id int64
	err := db.QueryRow(
		`SELECT id FROM credentials WHERE provider = ? AND location = ?`,
		cred.Provider, cred.Location,
	).Scan(&id)

	if err == nil {

		//A later scan might be the first time an Identifier becomes known for
		//a credential originally matched only by location (for example: a
		//provider gains Identifier support in a future version).
		//COALESCE/NULLIF keeps whatever identifier is already stored if this
		//call didn't supply one
		_, err = db.Exec(
			`UPDATE credentials SET last_seen_at = ?, identifier = COALESCE(NULLIF(?, ''), identifier) WHERE id = ?`,
			now, cred.Identifier, id,
		)
		return id, err

	}
	if !errors.Is(err, sql.ErrNoRows) {

		return 0, err

	}

	res, err := db.Exec(
		`INSERT INTO credentials (provider, subtype, location, identifier, first_seen_at, last_seen_at)
		 VALUES (?, ?, ?, NULLIF(?, ''), ?, ?)`,
		cred.Provider, string(cred.Subtype), cred.Location, cred.Identifier, now, now,
	)
	if err != nil {

		return 0, err

	}

	return res.LastInsertId()

}
//GetCredential returns credentialID's provider and location; the two fields
//storage.AddIgnore/RemoveIgnore actually key off of. Used by
//internal/dashboard's ignore/unignore handlers, which only have a credential ID
//to work from (from the rendered page), not the full provider/location pair
//directly
func GetCredential(db *DB, credentialID int64) (provider, location string, err error) {

	err = db.QueryRow(
		`SELECT provider, location FROM credentials WHERE id = ?`, credentialID,
	).Scan(&provider, &location)

	return provider, location, err

}

//OtherCredential is a manually-tracked "Other" entry; a credential type deadkey
//has no real provider for at all. See cmd/deadkey/add.go: these get a
//credentials row (so they're tracked, can be ignored/relisted) but deliberately
//no assessment row ever. There is no real API behind them to check
type OtherCredential struct {

	ID          int64     `json:"id"`
	Location    string    `json:"location"`
	OtherName   string    `json:"other_name"`
	FirstSeenAt time.Time `json:"first_seen_at"`

}

//ListOtherCredentials returns every credential registered under the special
//"other" provider name. Used by cmd/deadkey/scan.go to show these in their own
//distinct section, never mixed into the normal Dead/Rotate/Keep output
func ListOtherCredentials(db *DB) ([]OtherCredential, error) {

	rows, err := db.Query(
		`SELECT id, location, identifier, first_seen_at FROM credentials WHERE provider = 'other' ORDER BY id`,
	)
	if err != nil {

		return nil, err

	}
	defer rows.Close()

	var out []OtherCredential
	for rows.Next() {

		var c OtherCredential
		var firstSeenAt string
		var otherName sql.NullString

		if err := rows.Scan(&c.ID, &c.Location, &otherName, &firstSeenAt); err != nil {

			return nil, err

		}
		c.OtherName = otherName.String
		if t, err := time.Parse(time.RFC3339, firstSeenAt); err == nil {

			c.FirstSeenAt = t

		}

		out = append(out, c)

	}

	return out, rows.Err()

}
