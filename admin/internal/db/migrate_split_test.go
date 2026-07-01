package db

import (
	"strings"
	"testing"
)

// TestSplitStatementsRespectsCommentsAndStrings guards that a ';' inside a
// trailing -- comment or a '...' string literal (e.g. a column/table COMMENT)
// does not split a statement in half -- the schema's COMMENT text legitimately
// contains semicolons (e.g. "expiry (unix seconds, UTC; 0 = never)").
func TestSplitStatementsRespectsCommentsAndStrings(t *testing.T) {
	sql := `
CREATE TABLE a (
    x INTEGER,  -- a note with a ; semicolon inside
    y INTEGER COMMENT 'value; with semicolon'
);
CREATE TABLE b (z INTEGER);
`
	stmts := splitStatements(sql)
	if len(stmts) != 2 {
		t.Fatalf("want 2 statements (a ; in a comment/string must not split), got %d: %#v", len(stmts), stmts)
	}
	if !strings.Contains(stmts[0], "CREATE TABLE a") || !strings.Contains(stmts[0], "COMMENT 'value; with semicolon'") {
		t.Errorf("statement 0 lost content: %q", stmts[0])
	}
	if !strings.Contains(stmts[1], "CREATE TABLE b") {
		t.Errorf("statement 1 wrong: %q", stmts[1])
	}
}
