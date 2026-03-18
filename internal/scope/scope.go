package scope

import (
	"bufio"
	"net/url"
	"os"
	"strings"
)

type rule struct {
	pattern string
	deny    bool
}

type Engine struct {
	rules []rule
}

func Load(path string) *Engine {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	e := &Engine{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := rule{pattern: strings.ToLower(line)}
		if strings.HasPrefix(line, "!") {
			r.deny = true
			r.pattern = strings.ToLower(line[1:])
		}
		e.rules = append(e.rules, r)
	}
	return e
}

func (e *Engine) Allow(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}

	host := strings.ToLower(u.Host)
	full := host + strings.ToLower(u.Path)

	for _, r := range e.rules {
		if r.deny && matches(r.pattern, host, full) {
			return false
		}
	}

	for _, r := range e.rules {
		if !r.deny && matches(r.pattern, host, full) {
			return true
		}
	}

	for _, r := range e.rules {
		if !r.deny {
			return false
		}
	}
	return true
}

func matches(pattern, host, full string) bool {
	if strings.Contains(pattern, "/") {
		return strings.HasPrefix(full, pattern)
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	return host == pattern
}
