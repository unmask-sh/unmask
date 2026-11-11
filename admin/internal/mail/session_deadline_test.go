package mail

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// A relay that takes the connection and then says nothing: the dial had a
// timeout and nothing after it did, so the send -- an invitation, a test
// send, the scheduled digest -- waited for as long as the connection
// lived.  The session now has a deadline.
func TestSilentRelayEndsTheSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(5 * time.Second) // no greeting
	}()
	old := smtpSessionTimeout
	smtpSessionTimeout = 300 * time.Millisecond
	defer func() { smtpSessionTimeout = old }()
	m := New(Config{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, FromAddress: "notify@example.com"})
	start := time.Now()
	err = m.Send("dest@example.com", "s", "b")
	if err == nil {
		t.Fatal("a silent relay reported a sent message")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the send waited %v on a silent relay", took)
	}
}

// The relay accepted the message (DATA answered 250) and the QUIT then
// failed: the message is out, so the send reports success -- a failure here
// would be sent again and arrive twice.
func TestQuitAfterAcceptedIsNotAFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		fmt.Fprintf(conn, "220 stub ESMTP\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				fmt.Fprintf(conn, "250 stub\r\n")
			case cmd == "DATA":
				fmt.Fprintf(conn, "354 go\r\n")
				for {
					dl, err := r.ReadString('\n')
					if err != nil || strings.TrimRight(dl, "\r\n") == "." {
						break
					}
				}
				fmt.Fprintf(conn, "250 queued\r\n")
			case cmd == "QUIT":
				return // the connection drops before the 221
			default:
				fmt.Fprintf(conn, "250 OK\r\n")
			}
		}
	}()
	m := New(Config{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, FromAddress: "notify@example.com"})
	if err := m.Send("dest@example.com", "s", "b"); err != nil {
		t.Errorf("an accepted message reported as failed: %v", err)
	}
}
