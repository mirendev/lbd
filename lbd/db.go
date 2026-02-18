package lbd

import (
	"database/sql"
	"fmt"
)

// OpenDB opens (or creates) a SQLite database at dbPath, enables WAL mode,
// and ensures the run_hashes and lbd_labels tables exist.
func OpenDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting journal mode: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS run_hashes (
		run_offset INTEGER PRIMARY KEY,
		sha256     TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating run_hashes table: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS lbd_labels (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating lbd_labels table: %w", err)
	}

	return db, nil
}

// GetLabel reads a label value from the lbd_labels table.
// Returns ("", nil) if the key is not found.
func GetLabel(db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRow("SELECT value FROM lbd_labels WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading label %q: %w", key, err)
	}
	return value, nil
}

// SetLabel upserts a key/value pair in the lbd_labels table.
func SetLabel(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT INTO lbd_labels (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("setting label %q: %w", key, err)
	}
	return nil
}
