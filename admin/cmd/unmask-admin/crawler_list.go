// update-crawler-list: monperrus/crawler-user-agents から最新 JSON を取得.
//
// embed 同梱の crawler-user-agents.json を更新するには binary 再 build が
// 必要だが、 admin 側は環境変数 UNMASK_CRAWLER_UA_JSON で外部 path を優先
// 読み込みできる (= classify package が見る).
//
// 使い方:
//
//	unmask-admin update-crawler-list -out /etc/unmask/crawler-user-agents.json
//	systemctl restart unmask-admin   # cache を取り直すため
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const crawlerListURL = "https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json"

func cmdUpdateCrawlerList(args []string) error {
	fs := flag.NewFlagSet("update-crawler-list", flag.ExitOnError)
	out := fs.String("out", "-", "output path (- = stdout)")
	url := fs.String("url", crawlerListURL, "source URL")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP timeout")
	_ = fs.Parse(args)

	cli := &http.Client{Timeout: *timeout}
	req, _ := http.NewRequest(http.MethodGet, *url, nil)
	req.Header.Set("User-Agent", "unmask-admin/"+Version)
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return err
	}
	if len(body) < 1024 {
		return fmt.Errorf("response too small (%d bytes), aborting", len(body))
	}

	if *out == "-" {
		os.Stdout.Write(body)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(body), *out)
	return nil
}
