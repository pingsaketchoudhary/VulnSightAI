package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

type ScanResult struct {
	ID        int             `json:"id"`
	Target    string          `json:"target"`
	Timestamp string          `json:"timestamp"`
	ScanData  json.RawMessage `json:"scan_data"`
}

// InitDB initializes the SQLite database
func InitDB(filepath string) error {
	var err error
	DB, err = sql.Open("sqlite3", filepath)
	if err != nil {
		return err
	}

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		timestamp TEXT NOT NULL,
		scan_data TEXT NOT NULL
	);
	`
	_, err = DB.Exec(createTableQuery)
	if err != nil {
		return fmt.Errorf("could not create table: %v", err)
	}

	log.Println("Database initialized successfully.")
	return nil
}

// SaveScanResult saves a new scan result to the DB
func SaveScanResult(target string, scanData interface{}) (int64, error) {
	stmt, err := DB.Prepare("INSERT INTO scans(target, timestamp, scan_data) VALUES(?, ?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	jsonData, err := json.Marshal(scanData)
	if err != nil {
		return 0, err
	}

	res, err := stmt.Exec(target, timestamp, string(jsonData))
	if err != nil {
		return 0, err
	}

	return res.LastInsertId()
}

// GetAllScans retrieves past scans without parsing the full JSON
func GetAllScans() ([]ScanResult, error) {
	rows, err := DB.Query("SELECT id, target, timestamp FROM scans ORDER BY timestamp DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []ScanResult
	for rows.Next() {
		var s ScanResult
		if err := rows.Scan(&s.ID, &s.Target, &s.Timestamp); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, nil
}

// Close closes the database connection
func Close() {
	if DB != nil {
		DB.Close()
	}
}

// GetScanByID retrieves a specific scan by ID including its raw scan data
func GetScanByID(id int) (*ScanResult, error) {
	var s ScanResult
	var scanDataStr string
	err := DB.QueryRow("SELECT id, target, timestamp, scan_data FROM scans WHERE id = ?", id).Scan(&s.ID, &s.Target, &s.Timestamp, &scanDataStr)
	if err != nil {
		return nil, err
	}
	s.ScanData = json.RawMessage(scanDataStr)
	return &s, nil
}
