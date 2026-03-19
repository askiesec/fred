package dedup

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/askiesec/fred/internal/params"
)

var (
	reUUID = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	reHex  = regexp.MustCompile(`(?i)[0-9a-f]{32,}`)
	reInt  = regexp.MustCompile(`/\d+`)
)

var staticExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".webp": true, ".avif": true, ".ico": true, ".svg": true,
	".css": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".mp3": true, ".webm": true,
	".zip": true, ".tar": true, ".gz": true, ".br": true,
	".map": true, ".ts": true, ".pdf": true,
}

type Engine struct {
	seen sync.Map
}

func New() *Engine { return &Engine{} }

func (e *Engine) IsUnique(raw string) bool {
	fp := fingerprint(raw)
	if fp == "" {
		return false
	}
	_, loaded := e.seen.LoadOrStore(fp, struct{}{})
	return !loaded
}

func fingerprint(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if u.Hostname() == "" {
		return ""
	}

	host := strings.ToLower(u.Hostname())
	host = strings.TrimRight(host, ".")

	if port := u.Port(); port != "" {
		if !(u.Scheme == "https" && port == "443") && !(u.Scheme == "http" && port == "80") {
			host += ":" + port
		}
	}

	// decode percent-encoding before normalizing so that
	// /%CB%93%E2%86%92artists.php and /artists.php collapse to the same key
	p := u.Path
	if decoded, err := url.PathUnescape(p); err == nil {
		p = decoded
	}
	p = path.Clean(strings.ToLower(p))
	if p == "." {
		p = ""
	}

	if isNoise(p) {
		return ""
	}

	if staticExts[ext(p)] {
		return ""
	}

	p = reUUID.ReplaceAllString(p, "/{uuid}")
	p = reHex.ReplaceAllString(p, "/{hex}")
	p = reInt.ReplaceAllString(p, "/{n}")

	parts := make([]string, 0, len(u.Query()))
	for k, vals := range u.Query() {
		kl := strings.ToLower(k)
		if params.IsTracking(kl) {
			continue
		}
		if params.IsStructural(kl) && len(vals) > 0 {
			parts = append(parts, fmt.Sprintf("%s=%s", kl, strings.ToLower(vals[0])))
		} else {
			parts = append(parts, kl)
		}
	}
	sort.Strings(parts)

	return host + p + "?" + strings.Join(parts, "&")
}

// isNoise rejects paths that are clearly not real endpoints —
// payloads, scanner artifacts, and concatenated URLs from Wayback Machine.
func isNoise(p string) bool {
	// URL concatenated into path — scanner artifact
	if strings.Contains(p, "http://") || strings.Contains(p, "https://") {
		return true
	}
	// HTML chars and shell specials never appear in real paths
	if strings.ContainsAny(p, "<>`{}|\\^[]") {
		return true
	}
	// spaces after decoding are never real endpoints
	if strings.Contains(p, " ") {
		return true
	}
	// single char paths — comma, backtick, ampersand etc
	if len(strings.Trim(p, "/")) <= 1 && p != "/" {
		return true
	}
	// non-ASCII characters — virtually always Wayback garbage
	for _, c := range p {
		if c > 127 {
			return true
		}
	}
	// repeated special chars — fuzz artifacts
	if strings.Contains(p, "***") || strings.Contains(p, ">>>") {
		return true
	}
	return false
}

func ext(p string) string {
	for i := len(p) - 1; i >= 0 && p[i] != '/'; i-- {
		if p[i] == '.' {
			return p[i:]
		}
	}
	return ""
}
