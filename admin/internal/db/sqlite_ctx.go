package db

// The SQLite driver (modernc.org/sqlite) watches a query's context only
// while the statement takes its first step: the goroutine it starts to
// interrupt the statement when the context ends is stopped as the driver's
// QueryContext returns, and every row after the first is stepped in
// rows.Next with nothing watching.  A query that does its work in one step
// -- a COUNT, a GROUP BY that gathers before it emits -- is cut short at its
// deadline; one that streams rows is not, and on a disk kept busy by an
// index build each row's pages come from the queue behind the build, so the
// dashboard's figures, their five-second budget long gone, stood for hours
// (2026-10-17, a seventeen-million-row table).
//
// So the pool is opened on a driver of this package's own that wraps the
// library's: the same connections, the same statements, the same rows, with
// one watch per query that lives from the query's start to the rows' close
// and calls sqlite3_interrupt on the connection when the context ends.  The
// interrupt is the library's own mechanism (sqlite3_interrupt is safe from
// any thread); the handle it needs is the connection's, read from the
// library's connection by reflection, since the library exports neither it
// nor an Interrupt.  A library whose connection has no such field leaves
// the watch off, and the first step's watch as it was.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"log"
	"reflect"
	"sync"

	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

// sqliteDriverName is the name the pool is opened by.
const sqliteDriverName = "unmask-sqlite"

func init() {
	// The library's driver is the one registered as "sqlite"; sql.Open
	// opens nothing, it only hands the registered driver back.
	probe, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		panic("sqlite driver: " + err.Error())
	}
	inner := probe.Driver()
	_ = probe.Close()
	sql.Register(sqliteDriverName, &watchedDriver{inner: inner})
}

type watchedDriver struct{ inner driver.Driver }

func (d *watchedDriver) Open(name string) (driver.Conn, error) {
	c, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &watchedConn{Conn: c, db: sqliteHandle(c)}, nil
}

// sqliteHandle is the library connection's sqlite3* (its unexported db
// field), 0 when it cannot be read.
var sqliteHandleWarned sync.Once

func sqliteHandle(c driver.Conn) uintptr {
	v := reflect.ValueOf(c)
	if v.Kind() == reflect.Ptr && !v.IsNil() {
		v = v.Elem()
	}
	if v.Kind() == reflect.Struct {
		if f := v.FieldByName("db"); f.IsValid() && f.Kind() == reflect.Uintptr {
			return uintptr(f.Uint())
		}
	}
	sqliteHandleWarned.Do(func() {
		log.Printf("sqlite: the driver's connection has no db handle to read; queries are watched for their first step only")
	})
	return 0
}

// watchedConn is the library's connection with its queries' rows watched.
// The optional interfaces database/sql looks for are forwarded, so the
// pool treats it exactly as the library's own.
type watchedConn struct {
	driver.Conn
	db uintptr
}

func (c *watchedConn) Prepare(query string) (driver.Stmt, error) {
	s, err := c.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &watchedStmt{Stmt: s, db: c.db}, nil
}

func (c *watchedConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	var s driver.Stmt
	var err error
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		s, err = p.PrepareContext(ctx, query)
	} else {
		s, err = c.Conn.Prepare(query)
	}
	if err != nil {
		return nil, err
	}
	return &watchedStmt{Stmt: s, db: c.db}, nil
}

func (c *watchedConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.Conn.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.Conn.Begin() //nolint:staticcheck // the fallback database/sql itself takes
}

func (c *watchedConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if e, ok := c.Conn.(driver.ExecerContext); ok {
		return e.ExecContext(ctx, query, args) // one step, watched by the library throughout
	}
	return nil, driver.ErrSkip
}

func (c *watchedConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	q, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	w := startWatch(ctx, c.db)
	r, err := q.QueryContext(ctx, query, args)
	if err != nil {
		w.end()
		return nil, err
	}
	return &watchedRows{Rows: r, watch: w}, nil
}

func (c *watchedConn) Ping(ctx context.Context) error {
	if p, ok := c.Conn.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (c *watchedConn) ResetSession(ctx context.Context) error {
	if r, ok := c.Conn.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *watchedConn) IsValid() bool {
	if v, ok := c.Conn.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

// watchedStmt is a prepared statement whose queries' rows are watched.
type watchedStmt struct {
	driver.Stmt
	db uintptr
}

func (s *watchedStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if e, ok := s.Stmt.(driver.StmtExecContext); ok {
		return e.ExecContext(ctx, args)
	}
	return nil, driver.ErrSkip
}

func (s *watchedStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	q, ok := s.Stmt.(driver.StmtQueryContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	w := startWatch(ctx, s.db)
	r, err := q.QueryContext(ctx, args)
	if err != nil {
		w.end()
		return nil, err
	}
	return &watchedRows{Rows: r, watch: w}, nil
}

// watchedRows is the library's rows with the watch that ends at Close.
type watchedRows struct {
	driver.Rows
	watch *ctxWatch
}

func (r *watchedRows) Close() error {
	r.watch.end()
	return r.Rows.Close()
}

// The column type interfaces database/sql asks the rows for, forwarded.
func (r *watchedRows) ColumnTypeDatabaseTypeName(i int) string {
	if x, ok := r.Rows.(driver.RowsColumnTypeDatabaseTypeName); ok {
		return x.ColumnTypeDatabaseTypeName(i)
	}
	return ""
}

func (r *watchedRows) ColumnTypeLength(i int) (int64, bool) {
	if x, ok := r.Rows.(driver.RowsColumnTypeLength); ok {
		return x.ColumnTypeLength(i)
	}
	return 0, false
}

func (r *watchedRows) ColumnTypeNullable(i int) (bool, bool) {
	if x, ok := r.Rows.(driver.RowsColumnTypeNullable); ok {
		return x.ColumnTypeNullable(i)
	}
	return false, false
}

func (r *watchedRows) ColumnTypePrecisionScale(i int) (int64, int64, bool) {
	if x, ok := r.Rows.(driver.RowsColumnTypePrecisionScale); ok {
		return x.ColumnTypePrecisionScale(i)
	}
	return 0, 0, false
}

func (r *watchedRows) ColumnTypeScanType(i int) reflect.Type {
	if x, ok := r.Rows.(driver.RowsColumnTypeScanType); ok {
		return x.ColumnTypeScanType(i)
	}
	return reflect.TypeOf(new(any)).Elem()
}

// ctxWatch interrupts the connection's running statement when the context
// ends, unless the query is over by then.  mu orders the two: an end() that
// has begun is never followed by an interrupt (which, on a connection that
// has moved on, could hit an unrelated statement).
type ctxWatch struct {
	mu   sync.Mutex
	over bool
	stop chan struct{}
}

func startWatch(ctx context.Context, db uintptr) *ctxWatch {
	if db == 0 || ctx == nil || ctx.Done() == nil {
		return nil
	}
	w := &ctxWatch{stop: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			w.mu.Lock()
			if !w.over {
				tls := libc.NewTLS()
				sqlite3.Xsqlite3_interrupt(tls, db)
				tls.Close()
			}
			w.mu.Unlock()
		case <-w.stop:
		}
	}()
	return w
}

func (w *ctxWatch) end() {
	if w == nil {
		return
	}
	w.mu.Lock()
	if !w.over {
		w.over = true
		close(w.stop)
	}
	w.mu.Unlock()
}
