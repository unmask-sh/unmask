package dashboard

// rowsScanner is the slice of *sql.Rows the EXPLAIN helpers use.
type rowsScanner interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
}
