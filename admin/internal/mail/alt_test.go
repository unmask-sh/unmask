package mail

import (
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

// A message with both parts is multipart/alternative: the text first, the
// HTML last, each readable back as it was written -- Japanese, long lines and
// all.  The subject stays one header however long it is, in encoded-words of
// at most 75 characters.
func TestBuildAltMessage(t *testing.T) {
	cfg := Config{Host: "smtp.example.test", FromAddress: "no-reply@example.test", FromName: "unmask テスト"}
	subject := "[unmask:web1] challenge を通れない訪問者がいる可能性があります (直近 10 分)"
	text := "直近 10 分で、challenge を実行した 6 件のアドレスのうち 5 件が通れていません。\n" + strings.Repeat("長い行", 200) + "\n"
	html := "<p>" + strings.Repeat("<b>太字</b>", 300) + "</p>"
	raw := buildAltMessage(cfg, "ops@example.test", subject, text, html)

	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	dec := new(mime.WordDecoder)
	got, err := dec.DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || got != subject {
		t.Errorf("subject = %q (%v), want %q", got, err, subject)
	}
	for _, line := range strings.Split(string(raw), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("a line of %d octets", len(line))
		}
		if strings.HasPrefix(line, "Subject:") || strings.HasPrefix(line, " =?utf-8?B?") {
			for _, w := range strings.Fields(strings.TrimPrefix(line, "Subject:")) {
				if len(w) > 75 {
					t.Errorf("an encoded-word of %d characters: %s", len(w), w)
				}
			}
		}
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q (%v)", mt, err)
	}
	r := multipart.NewReader(msg.Body, params["boundary"])
	var types, bodies []string
	for {
		p, err := r.NextPart() // decodes quoted-printable
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p)
		types = append(types, p.Header.Get("Content-Type"))
		bodies = append(bodies, string(b))
	}
	if len(types) != 2 || !strings.HasPrefix(types[0], "text/plain") || !strings.HasPrefix(types[1], "text/html") {
		t.Fatalf("parts = %q, want text then html", types)
	}
	if strings.ReplaceAll(bodies[0], "\r\n", "\n") != text || bodies[1] != html {
		t.Error("a part does not read back as written")
	}
}

// A short ASCII subject is left as it is; a short non-ASCII one is one word.
func TestEncodeHeaderWords(t *testing.T) {
	if got := encodeHeader("[unmask] over-block"); got != "[unmask] over-block" {
		t.Errorf("ASCII subject = %q", got)
	}
	if got := encodeHeader("短い件名"); strings.Count(got, "=?utf-8?B?") != 1 {
		t.Errorf("short subject = %q, want one encoded-word", got)
	}
}
