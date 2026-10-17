// Package config reads the greetd configuration file, so the same
// /etc/greetd/config.toml drives sinty-logind.
package config

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// Session is a command run for a user.
type Session struct {
	Command string
	User    string
}

// Config is the part of the greetd configuration sinty-logind uses.
type Config struct {
	VT      int
	Default Session
	Initial *Session
}

// Path is the configuration file greetd and sinty-logind share.
const Path = "/etc/greetd/config.toml"

// Load reads a configuration file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads the [terminal], [default_session] and [initial_session]
// tables. Unknown tables and keys are ignored.
func Parse(r io.Reader) (*Config, error) {
	cfg := &Config{VT: 1, Default: Session{User: "greeter"}}
	section := ""
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "initial_session" && cfg.Initial == nil {
				cfg.Initial = &Session{User: "root"}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = unquote(strings.TrimSpace(value))
		switch section {
		case "terminal":
			if key == "vt" {
				if n, err := strconv.Atoi(value); err == nil {
					cfg.VT = n
				}
			}
		case "default_session":
			assign(&cfg.Default, key, value)
		case "initial_session":
			assign(cfg.Initial, key, value)
		}
	}
	return cfg, scanner.Err()
}

func assign(s *Session, key, value string) {
	switch key {
	case "command":
		s.Command = value
	case "user":
		s.User = value
	}
}

func unquote(v string) string {
	if i := strings.Index(v, " #"); i >= 0 && !strings.HasPrefix(v, `"`) {
		v = strings.TrimSpace(v[:i])
	}
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		if s, err := strconv.Unquote(v); err == nil && v[0] == '"' {
			return s
		}
		return v[1 : len(v)-1]
	}
	return v
}
