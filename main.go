package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/askiesec/fred/internal/dedup"
	"github.com/askiesec/fred/internal/detect"
	"github.com/askiesec/fred/internal/entropy"
	"github.com/askiesec/fred/internal/output"
	"github.com/askiesec/fred/internal/params"
	"github.com/askiesec/fred/internal/scope"
)

// set by build.sh via -ldflags
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

type config struct {
	input      string
	out        string
	format     string
	scopeFile  string
	oosFile    string
	secretsOut string
	workers    int
	stream     bool
	onlyParams bool
}

func main() {
	cfg := config{}

	showVersion := flag.Bool("version", false, "show version and exit")
	flag.StringVar(&cfg.input, "i", "", "input file (default: stdin)")
	flag.StringVar(&cfg.out, "o", "", "output file (default: stdout)")
	flag.StringVar(&cfg.format, "f", "txt", "output format: txt, json, csv")
	flag.StringVar(&cfg.scopeFile, "scope", "", "scope file (*.target.com, !deny rules)")
	flag.StringVar(&cfg.oosFile, "oos-file", "", "write out-of-scope URLs here")
	flag.StringVar(&cfg.secretsOut, "secrets-out", "", "write high-entropy params here")
	flag.IntVar(&cfg.workers, "workers", 4, "worker goroutines")
	flag.BoolVar(&cfg.stream, "stream", false, "print as processed, skip sorting")
	flag.BoolVar(&cfg.onlyParams, "p", false, "only URLs that have query params")
	flag.Parse()

	if *showVersion {
		fmt.Printf("fred %s (%s) built %s\n", version, commit, buildTime)
		os.Exit(0)
	}

	cfg.format = strings.ToLower(cfg.format)
	if cfg.format != "txt" && cfg.format != "json" && cfg.format != "csv" {
		die("unknown format %q, use txt, json or csv", cfg.format)
	}

	in := openInput(cfg.input)
	defer in.Close()

	mainOut := openOutput(cfg.out)
	if mainOut != os.Stdout {
		defer mainOut.Close()
	}

	oosW := sideWriter(cfg.oosFile)
	secW := sideWriter(cfg.secretsOut)
	if oosW != nil {
		defer oosW.Flush()
	}
	if secW != nil {
		defer secW.Flush()
	}

	sc := scope.Load(cfg.scopeFile)
	d := dedup.New()
	e := entropy.New()
	det := detect.New()

	lines := make(chan string, cfg.workers*200)
	results := make(chan output.Result, cfg.workers*200)

	go readLines(in, lines)

	var wg sync.WaitGroup
	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for raw := range lines {
				r, drop := process(raw, sc, d, e, det)
				if !drop {
					results <- r
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	w := newWriter(cfg.format, mainOut)
	w.header()

	var collected []output.Result

	for r := range results {
		if r.IsSecret && secW != nil {
			secW.WriteString(r.URL + "\n")
		}
		if r.OutOfScope {
			if oosW != nil {
				oosW.WriteString(r.URL + "\n")
			}
			continue
		}
		if cfg.onlyParams && !r.HasParams {
			continue
		}
		if cfg.stream {
			w.write(r)
		} else {
			collected = append(collected, r)
		}
	}

	if !cfg.stream {
		sort.Slice(collected, func(i, j int) bool {
			return collected[i].URL < collected[j].URL
		})
		for _, r := range collected {
			w.write(r)
		}
	}

	w.flush()

	if cfg.out != "" {
		fmt.Fprintf(os.Stderr, "%d URLs -> %s (%s)\n", len(collected), cfg.out, cfg.format)
	}
}

func process(
	raw string,
	sc *scope.Engine,
	d *dedup.Engine,
	e *entropy.Engine,
	det *detect.Engine,
) (output.Result, bool) {
	r := output.Result{URL: raw}

	if !d.IsUnique(raw) {
		return r, true
	}
	if sc != nil && !sc.Allow(raw) {
		r.OutOfScope = true
		return r, false
	}

	// strip tracking params from the URL before output
	r.URL = params.StripTracking(raw)

	u, err := url.Parse(r.URL)
	if err != nil {
		return r, true
	}

	r.Tech = det.Identify(u)
	r.HasParams = len(u.RawQuery) > 0

	er := e.AnalyzeParsed(u)
	r.IsSecret = er.HasHighEntropy
	r.EntropyParams = er.Suspicious

	return r, false
}

func readLines(f *os.File, ch chan<- string) {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			ch <- line
		}
	}
	close(ch)
}

func openInput(path string) *os.File {
	if path == "" {
		return os.Stdin
	}
	f, err := os.Open(path)
	if err != nil {
		die("open input: %v", err)
	}
	return f
}

func openOutput(path string) *os.File {
	if path == "" {
		return os.Stdout
	}
	f, err := os.Create(path)
	if err != nil {
		die("create output: %v", err)
	}
	return f
}

func sideWriter(path string) *bufio.Writer {
	if path == "" {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		die("create file %s: %v", path, err)
	}
	return bufio.NewWriter(f)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fred: "+format+"\n", args...)
	os.Exit(1)
}

type writer interface {
	header()
	write(output.Result)
	flush()
}

func newWriter(format string, f *os.File) writer {
	bw := bufio.NewWriter(f)
	switch format {
	case "json":
		return &jsonWriter{w: bw}
	case "csv":
		return &csvWriter{w: csv.NewWriter(bw), raw: bw}
	default:
		return &txtWriter{w: bw}
	}
}

type txtWriter struct{ w *bufio.Writer }

func (t *txtWriter) header()               {}
func (t *txtWriter) write(r output.Result) { fmt.Fprintln(t.w, r.URL) }
func (t *txtWriter) flush()                { t.w.Flush() }

type jsonWriter struct{ w *bufio.Writer }

func (j *jsonWriter) header() {}
func (j *jsonWriter) write(r output.Result) {
	b, _ := json.Marshal(r)
	j.w.Write(b)
	j.w.WriteByte('\n')
}
func (j *jsonWriter) flush() { j.w.Flush() }

type csvWriter struct {
	w   *csv.Writer
	raw *bufio.Writer
}

func (c *csvWriter) header() {
	c.w.Write([]string{"url", "tech", "has_params", "is_secret", "entropy_params"})
}

func (c *csvWriter) write(r output.Result) {
	c.w.Write([]string{
		r.URL,
		r.Tech,
		fmt.Sprintf("%t", r.HasParams),
		fmt.Sprintf("%t", r.IsSecret),
		strings.Join(r.EntropyParams, ";"),
	})
}

func (c *csvWriter) flush() {
	c.w.Flush()
	c.raw.Flush()
}
