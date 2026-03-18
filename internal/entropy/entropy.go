package entropy

import (
	"math"
	"net/url"
	"strings"
)

// Shannon entropy reference points:
//   "hello"          ~2.3
//   "password123"    ~3.0
//   random hex 32c   ~3.9
//   base64 JWT       ~4.3
//
// 3.5 is a reasonable cutoff — low enough to catch real tokens,
// high enough to avoid flagging things like "hello-world-test".
// Minimum length of 12 avoids short strings that hit 3.5 by accident.

const (
	threshold = 3.5
	minLen    = 12
)

type Result struct {
	HasHighEntropy bool
	Suspicious     []string
}

type Engine struct{}

func New() *Engine { return &Engine{} }

// Analyze parses the URL internally — use AnalyzeParsed if you already have *url.URL.
func (e *Engine) Analyze(raw string) Result {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Result{}
	}
	return e.AnalyzeParsed(u)
}

func (e *Engine) AnalyzeParsed(u *url.URL) Result {
	var res Result
	for k, vals := range u.Query() {
		for _, v := range vals {
			if len(v) >= minLen && shannon(v) >= threshold {
				res.HasHighEntropy = true
				res.Suspicious = append(res.Suspicious, k)
				break
			}
		}
	}
	return res
}

func shannon(s string) float64 {
	freq := make(map[rune]int, len(s))
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}
