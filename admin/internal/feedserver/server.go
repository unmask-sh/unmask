package feedserver

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Server: state on the hub side.  Open() opens the DB and migrates; Close()
// closes it.
//
// Safe to call from multiple goroutines (= sql.DB pools connections).  The
// register / submit endpoints bind ServeRegister / ServeSubmit to a ServeMux.
type Server struct {
	cfg     settings.FeedServer
	db      *sql.DB
	logger  *log.Logger
	mu      sync.Mutex            // guards registerByIP updates
	regByIP map[string]time.Time  // per-IP rate limit for the register endpoint
}

// Open: open SQLite and migrate schema.  Returns error if cfg.DBPath is empty.
func Open(cfg settings.FeedServer, logger *log.Logger) (*Server, error) {
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("feedserver: db_path is empty")
	}
	conn, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", cfg.DBPath, err)
	}
	conn.SetMaxOpenConns(4) // sqlite: 4 conns is plenty even single-process
	if err := migrate(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Server{
		cfg:     cfg,
		db:      conn,
		logger:  logger,
		regByIP: make(map[string]time.Time),
	}, nil
}

// Close: close the internal DB.
func (s *Server) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DB: returns the internal *sql.DB (= for direct queries from the aggregation cron).
func (s *Server) DB() *sql.DB { return s.db }

// Config: returns settings (= used to read judge_mode / min_reports / expiry
// during aggregation).
func (s *Server) Config() settings.FeedServer { return s.cfg }

func (s *Server) logf(format string, args ...any) {
	if s.logger == nil {
		log.Printf(format, args...)
		return
	}
	s.logger.Printf(format, args...)
}
