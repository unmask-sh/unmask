// Package settings: YAML config loading.
//
// 設定ファイルは /etc/unmask/config.yml をデフォルトに探す.
// 環境変数 UNMASK_CONFIG で override 可能.
//
// 構造:
//
//	db:
//	  driver: sqlite | mariadb
//	  sqlite_path: /var/lib/unmask/unmask.sqlite
//	  mariadb:
//	    host: 127.0.0.1
//	    port: 3306
//	    user: unmask
//	    password: ...
//	    database: unmask
//	secret:
//	  bv_secret: <random 32+ chars>      # _bv cookie HMAC-SHA1 key
//	  captcha_secret_base: <random>      # math captcha token HMAC-SHA256 base
//	challenge:
//	  cookie_days: 3
//	  captcha_score_threshold: 0.5
//	  debug_rate_limit_per_5min: 20
//	  challenge_html_path: ""            # 空なら embed 同梱版を使う
//	server:
//	  bind: 127.0.0.1
//	  port: 8765
//	  base_path: /unmask                 # admin app の URL prefix
//	  admin_token: ""                    # 空なら無認証 (= bind 127.0.0.1 前提)
package settings

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

var defaultPaths = []string{
	"/etc/unmask/config.yml",
	"/etc/unmask/config.yaml",
}

type DB struct {
	Driver     string  `yaml:"driver"`
	SQLitePath string  `yaml:"sqlite_path"`
	MariaDB    MariaDB `yaml:"mariadb"`
}

type MariaDB struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
}

type Secret struct {
	BVSecret          string `yaml:"bv_secret"`
	CaptchaSecretBase string `yaml:"captcha_secret_base"`
}

type Challenge struct {
	CookieDays              int     `yaml:"cookie_days"`
	CaptchaScoreThreshold   float64 `yaml:"captcha_score_threshold"`
	DebugRateLimitPer5Min   int     `yaml:"debug_rate_limit_per_5min"`
	ChallengeHTMLPath       string  `yaml:"challenge_html_path"`
}

type Server struct {
	Bind       string `yaml:"bind"`
	Port       int    `yaml:"port"`
	BasePath   string `yaml:"base_path"`
	AdminToken string `yaml:"admin_token"`
}

type Settings struct {
	DB        DB        `yaml:"db"`
	Secret    Secret    `yaml:"secret"`
	Challenge Challenge `yaml:"challenge"`
	Server    Server    `yaml:"server"`
}

func defaults() Settings {
	return Settings{
		DB: DB{
			Driver:     "sqlite",
			SQLitePath: "/var/lib/unmask/unmask.sqlite",
			MariaDB: MariaDB{
				Host: "127.0.0.1", Port: 3306,
				User: "unmask", Database: "unmask",
			},
		},
		Challenge: Challenge{
			CookieDays:            3,
			CaptchaScoreThreshold: 0.5,
			DebugRateLimitPer5Min: 20,
		},
		Server: Server{
			Bind:     "127.0.0.1",
			Port:     8765,
			BasePath: "/unmask",
		},
	}
}

func findPath() string {
	if p := os.Getenv("UNMASK_CONFIG"); p != "" {
		return p
	}
	for _, p := range defaultPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// Load reads the config file (path or auto-detected) and overlays it on top
// of defaults. If no config file is found, defaults are returned.
//
// 未設定の secret は session 単位のランダム値で埋める (= 起動毎に変わるので
// production では config に書くこと. これは「立ち上げただけで動く」 体験のため).
func Load(path string) (Settings, error) {
	s := defaults()
	if path == "" {
		path = findPath()
	}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return s, fmt.Errorf("read %s: %w", path, err)
		}
		if err := yaml.Unmarshal(raw, &s); err != nil {
			return s, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if s.Secret.BVSecret == "" {
		s.Secret.BVSecret = randomHex(24)
	}
	if s.Secret.CaptchaSecretBase == "" {
		s.Secret.CaptchaSecretBase = randomHex(24)
	}
	return s, nil
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
