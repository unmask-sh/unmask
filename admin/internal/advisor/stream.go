package advisor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// streamIdle ends a streamed attempt that has gone quiet: no line from the
// provider for this long (the API's pings included) is a stall, not a
// model at work.  A variable so tests can shorten it.
var streamIdle = 2 * time.Minute

// errStreamCut is a stream that ended before its message did: the
// connection went away mid-answer.  Retried like a timeout.
var errStreamCut = errors.New("the provider's stream ended before the answer did")

// anthropicPost sends a Messages API request as a stream and returns the
// message the events built, in the shape of a non-streaming response
// (stop_reason, stop_details, content, usage), so the callers read it as
// before.
//
// Why a stream: at effort xhigh or max the model may think for minutes
// before it writes a word, and max_tokens must leave room for that
// (maxTokensFor).  A request that sends nothing for minutes is what idle
// connections drop; a stream carries the events and the API's pings as it
// goes, so a stalled provider is told from a slow answer: streamIdle
// without a line ends the attempt.  An answer that is not an event stream
// (a proxy that ignores "stream", a stub) is read as the JSON it is.
func anthropicPost(ctx context.Context, url string, headers map[string]string, body map[string]any) ([]byte, error) {
	streamed := make(map[string]any, len(body)+1)
	for k, v := range body {
		streamed[k] = v
	}
	streamed["stream"] = true
	buf, err := json.Marshal(streamed)
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stalled atomic.Bool
	idle := time.AfterFunc(streamIdle, func() { stalled.Store(true); cancel() })
	defer idle.Stop()
	stall := func(err error) error {
		if stalled.Load() {
			return fmt.Errorf("the provider sent nothing for %s: %w", streamIdle, context.DeadlineExceeded)
		}
		return err
	}
	req, err := http.NewRequestWithContext(sctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, stall(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("content-type"), "text/event-stream") {
		out, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			return nil, stall(err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, providerError(resp, out)
		}
		return out, nil
	}
	var m streamedMessage
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		idle.Reset(streamIdle)
		data, ok := bytes.CutPrefix(sc.Bytes(), []byte("data:"))
		if !ok {
			continue // "event:" names what the data's own "type" says; blank lines end an event
		}
		done, err := m.apply(bytes.TrimSpace(data))
		if err != nil {
			return nil, err
		}
		if done {
			return m.final()
		}
	}
	if err := sc.Err(); err != nil {
		return nil, stall(err)
	}
	return nil, stall(errStreamCut)
}

// streamedMessage is a message as its events build it: the blocks by
// index, a tool call's input as the JSON pieces arrive, the stop and the
// token counts.
type streamedMessage struct {
	blocks      []map[string]any
	inputs      map[int]*strings.Builder
	stopReason  string
	stopDetails json.RawMessage
	in, out     int
}

type streamUsage struct {
	Input  int `json:"input_tokens"`
	Output int `json:"output_tokens"`
}

// apply reads one event; done is the message's end.
func (m *streamedMessage) apply(data []byte) (done bool, err error) {
	var ev struct {
		Type    string `json:"type"`
		Index   int    `json:"index"`
		Message struct {
			Usage streamUsage `json:"usage"`
		} `json:"message"`
		ContentBlock map[string]any `json:"content_block"`
		Delta        struct {
			Type        string          `json:"type"`
			Text        string          `json:"text"`
			Thinking    string          `json:"thinking"`
			Signature   string          `json:"signature"`
			PartialJSON string          `json:"partial_json"`
			StopReason  string          `json:"stop_reason"`
			StopDetails json.RawMessage `json:"stop_details"`
		} `json:"delta"`
		Usage streamUsage `json:"usage"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &ev); err != nil {
		return false, fmt.Errorf("reading the provider's stream: %w", err)
	}
	block := func() map[string]any {
		if ev.Index >= 0 && ev.Index < len(m.blocks) {
			return m.blocks[ev.Index]
		}
		return nil
	}
	switch ev.Type {
	case "message_start":
		m.count(ev.Message.Usage)
	case "content_block_start":
		if ev.Index < 0 || ev.ContentBlock == nil {
			return false, fmt.Errorf("reading the provider's stream: a block without its start")
		}
		for len(m.blocks) <= ev.Index {
			m.blocks = append(m.blocks, nil)
		}
		m.blocks[ev.Index] = ev.ContentBlock
	case "content_block_delta":
		b := block()
		if b == nil {
			return false, fmt.Errorf("reading the provider's stream: a delta for block %d before its start", ev.Index)
		}
		switch ev.Delta.Type {
		case "text_delta":
			b["text"] = asString(b["text"]) + ev.Delta.Text
		case "thinking_delta":
			b["thinking"] = asString(b["thinking"]) + ev.Delta.Thinking
		case "signature_delta":
			b["signature"] = ev.Delta.Signature
		case "input_json_delta":
			if m.inputs == nil {
				m.inputs = map[int]*strings.Builder{}
			}
			if m.inputs[ev.Index] == nil {
				m.inputs[ev.Index] = &strings.Builder{}
			}
			m.inputs[ev.Index].WriteString(ev.Delta.PartialJSON)
		}
	case "content_block_stop":
		// A tool call's input arrives as JSON in pieces; whole, it replaces
		// the empty object the block started with.
		if js, ok := m.inputs[ev.Index]; ok && block() != nil {
			var in any
			if err := json.Unmarshal([]byte(js.String()), &in); err == nil {
				m.blocks[ev.Index]["input"] = in
			}
		}
	case "message_delta":
		if ev.Delta.StopReason != "" {
			m.stopReason = ev.Delta.StopReason
		}
		if len(ev.Delta.StopDetails) > 0 && string(ev.Delta.StopDetails) != "null" {
			m.stopDetails = ev.Delta.StopDetails
		}
		m.count(ev.Usage)
	case "message_stop":
		return true, nil
	case "error":
		return false, streamError(ev.Error.Type, ev.Error.Message)
	}
	return false, nil
}

// count keeps the latest counts: message_delta's output count is the
// running total, not an increment.
func (m *streamedMessage) count(u streamUsage) {
	if u.Input > 0 {
		m.in = u.Input
	}
	if u.Output > 0 {
		m.out = u.Output
	}
}

// final is the message as a non-streaming response would have carried it.
func (m *streamedMessage) final() ([]byte, error) {
	content := make([]map[string]any, 0, len(m.blocks))
	for _, b := range m.blocks {
		if b != nil {
			content = append(content, b)
		}
	}
	msg := map[string]any{
		"stop_reason": m.stopReason,
		"content":     content,
		"usage":       map[string]int{"input_tokens": m.in, "output_tokens": m.out},
	}
	if len(m.stopDetails) > 0 {
		msg["stop_details"] = m.stopDetails
	}
	return json.Marshal(msg)
}

// streamError is an error event mid-stream, typed like the HTTP answer the
// same failure gets before a stream opens, so retryable treats both alike:
// overloaded and server errors are retried, the rest are not.
func streamError(typ, msg string) error {
	status := http.StatusBadRequest
	switch typ {
	case "overloaded_error":
		status = 529
	case "api_error":
		status = http.StatusInternalServerError
	case "rate_limit_error":
		status = http.StatusTooManyRequests
	}
	return &providerHTTPError{Status: status, StatusText: typ, Msg: msg}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
