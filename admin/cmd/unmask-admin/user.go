// user CLI sub-command:
//
//   unmask-admin user list
//   unmask-admin user create <username> [-role superadmin|admin|viewer] [-password PASS]
//   unmask-admin user reset-password <username> [-password PASS]
//   unmask-admin user set-role <username> <role>
//   unmask-admin user delete <username>
//
// If password is omitted, prompts on stdin (= entered twice in the terminal).
// Pass -password for non-interactive use, but note that it leaks into shell history.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

func cmdUser(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: unmask-admin user <list|create|reset-password|set-role|delete> ...")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list":
		return cmdUserList(rest)
	case "create":
		return cmdUserCreate(rest)
	case "reset-password":
		return cmdUserResetPassword(rest)
	case "set-role":
		return cmdUserSetRole(rest)
	case "delete":
		return cmdUserDelete(rest)
	default:
		return fmt.Errorf("unknown user sub-command: %s", sub)
	}
}

func openUserRepo(configPath string) (*user.Repository, *db.DB, error) {
	s, err := loadSettings(configPath)
	if err != nil {
		return nil, nil, err
	}
	conn, err := db.Open(s.DB)
	if err != nil {
		return nil, nil, fmt.Errorf("open db: %w", err)
	}
	return user.New(conn), conn, nil
}

func cmdUserList(args []string) error {
	fs := flag.NewFlagSet("user list", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	_ = fs.Parse(args)

	repo, conn, err := openUserRepo(*configPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	xs, err := repo.List(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("%-20s  %-12s  %-19s  %-19s\n", "username", "role", "created_at", "last_login")
	fmt.Printf("%s\n", strings.Repeat("-", 78))
	for _, u := range xs {
		last := "(never)"
		if u.LastLogin.Valid {
			last = u.LastLogin.Time.Format("2006-01-02 15:04:05")
		}
		fmt.Printf("%-20s  %-12s  %-19s  %-19s\n",
			u.Username, u.Role, u.CreatedAt.Format("2006-01-02 15:04:05"), last)
	}
	return nil
}

func cmdUserCreate(args []string) error {
	fs := flag.NewFlagSet("user create", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	role := fs.String("role", "admin", "superadmin | admin | viewer")
	passwordFlag := fs.String("password", "", "password (interactive prompt if omitted)")
	pos := parseMixed(fs, args)

	if len(pos) < 1 {
		return errors.New("usage: unmask-admin user create <username> [-role ...] [-password ...]")
	}
	username := pos[0]
	if !user.IsValidRole(*role) {
		return fmt.Errorf("invalid role: %q (must be superadmin / admin / viewer)", *role)
	}
	pass, err := resolvePassword(*passwordFlag, true)
	if err != nil {
		return err
	}

	repo, conn, err := openUserRepo(*configPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	u, err := repo.Create(context.Background(), username, pass, *role)
	if err != nil {
		return err
	}
	fmt.Printf("created user: id=%d username=%s role=%s\n", u.ID, u.Username, u.Role)
	return nil
}

func cmdUserResetPassword(args []string) error {
	fs := flag.NewFlagSet("user reset-password", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	passwordFlag := fs.String("password", "", "new password (interactive prompt if omitted)")
	pos := parseMixed(fs, args)

	if len(pos) < 1 {
		return errors.New("usage: unmask-admin user reset-password <username> [-password ...]")
	}
	username := pos[0]
	pass, err := resolvePassword(*passwordFlag, true)
	if err != nil {
		return err
	}

	repo, conn, err := openUserRepo(*configPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	u, err := repo.GetByUsername(context.Background(), username)
	if err != nil {
		return err
	}
	if err := repo.SetPassword(context.Background(), u.ID, pass); err != nil {
		return err
	}
	fmt.Printf("password reset: username=%s\n", username)
	return nil
}

func cmdUserSetRole(args []string) error {
	fs := flag.NewFlagSet("user set-role", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	pos := parseMixed(fs, args)

	if len(pos) < 2 {
		return errors.New("usage: unmask-admin user set-role <username> <superadmin|admin|viewer>")
	}
	username := pos[0]
	role := pos[1]
	if !user.IsValidRole(role) {
		return fmt.Errorf("invalid role: %q", role)
	}

	repo, conn, err := openUserRepo(*configPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	u, err := repo.GetByUsername(context.Background(), username)
	if err != nil {
		return err
	}
	if err := repo.SetRole(context.Background(), u.ID, role); err != nil {
		return err
	}
	fmt.Printf("role updated: username=%s role=%s\n", username, role)
	return nil
}

func cmdUserDelete(args []string) error {
	fs := flag.NewFlagSet("user delete", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	pos := parseMixed(fs, args)

	if len(pos) < 1 {
		return errors.New("usage: unmask-admin user delete <username>")
	}
	username := pos[0]

	repo, conn, err := openUserRepo(*configPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	u, err := repo.GetByUsername(context.Background(), username)
	if err != nil {
		return err
	}
	if err := repo.Delete(context.Background(), u.ID); err != nil {
		return err
	}
	fmt.Printf("deleted user: username=%s\n", username)
	return nil
}

// parseMixed: Go's flag.Parse stops at the first non-flag arg, but users want
// to write `cmd <positional> -flag=value` (= the natural shell order).  Helper
// that parses flags and positionals together by iterating parse calls.
func parseMixed(fs *flag.FlagSet, args []string) []string {
	positional := []string{}
	remaining := args
	for {
		if err := fs.Parse(remaining); err != nil {
			return positional
		}
		if fs.NArg() == 0 {
			return positional
		}
		positional = append(positional, fs.Arg(0))
		remaining = fs.Args()[1:]
	}
}

// resolvePassword: returns -password if given.  Otherwise prompts twice on
// terminal.  Echo is off (= input is hidden).
//
// When requireConfirm=true, asks for confirmation and checks both inputs
// match.  Used by reset / create.
func resolvePassword(flagValue string, requireConfirm bool) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	// terminal detection
	if !term.IsTerminal(int(syscall.Stdin)) {
		// Assume read from a pipe (= 1 line).
		s := bufio.NewScanner(os.Stdin)
		if !s.Scan() {
			return "", errors.New("password not provided (stdin empty)")
		}
		return strings.TrimRight(s.Text(), "\r\n"), nil
	}
	fmt.Print("password: ")
	b1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	pass := string(b1)
	if requireConfirm {
		fmt.Print("password (again): ")
		b2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", err
		}
		if string(b2) != pass {
			return "", errors.New("passwords do not match")
		}
	}
	if pass == "" {
		return "", errors.New("password is empty")
	}
	return pass, nil
}
