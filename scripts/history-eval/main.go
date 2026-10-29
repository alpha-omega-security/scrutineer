// Command history-eval measures the history skill's commit pre-filter and
// classifier against a labelled corpus of security-fix commits.
//
// The corpus lives outside this repository (-data) and is read-only. Labels
// are built from OSV GIT-range fix commits (advised positives) joined to
// population.json by ecosystem+package name, plus seeded random negatives
// from the same repositories' commit logs. Unadvised positives are accepted
// in labels.jsonl but not generated here; append them after hand-checking.
//
// Per-repository results name unannounced fixes in critical packages. They
// are written only under -out (default ./data/history-eval, which is
// gitignored) through os.Root, and must not be committed, posted or shared.
//
//	go run ./scripts/history-eval -data /Volumes/T9/cve-less-signals/data -mode labels
//	go run ./scripts/history-eval -data /Volumes/T9/cve-less-signals/data -mode prefilter
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maxLogRecord      = 1 << 20
	maxLogBytes       = 512 << 20
	scannerBuf        = 64 << 10
	fieldSep          = 0x1f
	recordSep         = 0x1e
	logFields         = 5
	outDirPerm        = 0o755
	defaultNegPerRepo = 20
)

// osvEcosystem maps an osv/<name>.jsonl stem to the population.json
// ecosystem key. Mirrors OSV_ECO in the corpus scripts.
var osvEcosystem = map[string]string{
	"npm": "npm", "PyPI": "pypi", "crates.io": "cargo", "RubyGems": "rubygems",
	"Maven": "maven", "Go": "go", "Packagist": "packagist", "NuGet": "nuget",
	"Hex": "hex", "Pub": "pub", "Hackage": "hackage", "CRAN": "cran",
	"SwiftURL": "swiftpm", "GitHub_Actions": "actions",
}

type label struct {
	SHA     string `json:"sha"`
	Repo    string `json:"repo"`
	RepoKey string `json:"repo_key"`
	Class   string `json:"class"`
	Source  string `json:"source,omitempty"`
	OSVRepo string `json:"osv_repo,omitempty"`
}

type logRecord struct {
	SHA     string
	Date    string
	Author  string
	Subject string
	Body    string
}

type pattern struct {
	Label     string `json:"label"`
	Ecosystem string `json:"ecosystem"`
	Pattern   string `json:"pattern"`
	Flags     int    `json:"flags"`
	re        *regexp.Regexp
}

type prefilterRow struct {
	label
	InLog   bool     `json:"in_log"`
	Matched bool     `json:"matched"`
	Terms   []string `json:"terms,omitempty"`
	Subject string   `json:"subject,omitempty"`
}

type population struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Repo      string `json:"repo"`
	Host      string `json:"host"`
}

type osvRecord struct {
	ID       string `json:"id"`
	Affected []struct {
		Name   string `json:"name"`
		Ranges []struct {
			Type   string `json:"type"`
			Repo   string `json:"repo"`
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

var shaRE = regexp.MustCompile(`^[0-9a-f]{40,64}$`)

func main() {
	var (
		dataDir   = flag.String("data", "", "corpus root (contains osv/, population.json, commits/)")
		outDir    = flag.String("out", "data/history-eval", "output directory for labels and results")
		mode      = flag.String("mode", "", "labels | prefilter | skill")
		skillsDir = flag.String("skills", "skills", "scrutineer skills root (for history_candidates.py patterns)")
		negPer    = flag.Int("neg-per-repo", defaultNegPerRepo, "random negative commits per labelled repo")
		seed      = flag.Int64("seed", 1, "negative-sample seed")
	)
	flag.Parse()
	if err := run(*mode, *dataDir, *outDir, *skillsDir, *negPer, *seed); err != nil {
		fmt.Fprintln(os.Stderr, "history-eval:", err)
		os.Exit(1)
	}
}

func run(mode, dataDir, outDir, skillsDir string, negPer int, seed int64) error {
	if dataDir == "" {
		return errors.New("-data is required")
	}
	if err := os.MkdirAll(outDir, outDirPerm); err != nil {
		return err
	}
	out, err := os.OpenRoot(outDir)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	switch mode {
	case "labels":
		labels, err := buildLabels(dataDir, negPer, seed)
		if err != nil {
			return err
		}
		return writeJSONL(out, "labels.jsonl", labels)
	case "prefilter":
		pats, err := loadPatterns(skillsDir)
		if err != nil {
			return err
		}
		labels, err := readLabels(out)
		if err != nil {
			return err
		}
		rows, err := scorePrefilter(dataDir, labels, pats)
		if err != nil {
			return err
		}
		if err := writeJSONL(out, "prefilter.jsonl", rows); err != nil {
			return err
		}
		return summarise(os.Stdout, rows, pats)
	case "skill":
		return errors.New("-mode skill: full-skill scoring needs per-repo clones; not implemented in this change")
	default:
		return fmt.Errorf("unknown -mode %q (want labels, prefilter, or skill)", mode)
	}
}

func repoKey(repo string) string {
	return strings.ReplaceAll(strings.ToLower(repo), "/", "_")
}

func buildLabels(dataDir string, negPer int, seed int64) ([]label, error) {
	pop, err := loadPopulation(filepath.Join(dataDir, "population.json"))
	if err != nil {
		return nil, err
	}
	positives, err := osvGitFixes(filepath.Join(dataDir, "osv"), pop)
	if err != nil {
		return nil, err
	}
	posByRepo := map[string]map[string]bool{}
	for _, l := range positives {
		if posByRepo[l.RepoKey] == nil {
			posByRepo[l.RepoKey] = map[string]bool{}
		}
		posByRepo[l.RepoKey][l.SHA] = true
	}
	repos := make([]string, 0, len(posByRepo))
	for k := range posByRepo {
		repos = append(repos, k)
	}
	sort.Strings(repos)
	rng := rand.New(rand.NewSource(seed))
	labels := append([]label(nil), positives...)
	for _, key := range repos {
		recs, err := readCommitLog(filepath.Join(dataDir, "commits", key+".log"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		repo := positives[indexOfRepo(positives, key)].Repo
		labels = append(labels, sampleNegatives(recs, posByRepo[key], repo, key, negPer, rng)...)
	}
	return labels, nil
}

func indexOfRepo(ls []label, key string) int {
	for i, l := range ls {
		if l.RepoKey == key {
			return i
		}
	}
	return 0
}

func sampleNegatives(recs []logRecord, exclude map[string]bool, repo, key string, n int, rng *rand.Rand) []label {
	pool := recs[:0:0]
	for _, r := range recs {
		if !exclude[r.SHA] {
			pool = append(pool, r)
		}
	}
	rng.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	if n > len(pool) {
		n = len(pool)
	}
	out := make([]label, 0, n)
	for _, r := range pool[:n] {
		out = append(out, label{SHA: r.SHA, Repo: repo, RepoKey: key, Class: "negative"})
	}
	return out
}

func loadPopulation(path string) (map[[2]string]population, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var rows []population
	if err := json.NewDecoder(f).Decode(&rows); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	idx := map[[2]string]population{}
	for _, p := range rows {
		if p.Repo == "" {
			continue
		}
		idx[[2]string{p.Ecosystem, strings.ToLower(p.Name)}] = p
	}
	return idx, nil
}

func osvGitFixes(dir string, pop map[[2]string]population) ([]label, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var labels []label
	seen := map[[2]string]bool{}
	for _, e := range entries {
		stem, ok := strings.CutSuffix(e.Name(), ".jsonl")
		if !ok || e.IsDir() {
			continue
		}
		eco, ok := osvEcosystem[stem]
		if !ok {
			continue
		}
		recs, err := readOSV(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			labels = appendGitFixes(labels, seen, r, eco, pop)
		}
	}
	sort.Slice(labels, func(i, j int) bool {
		if labels[i].RepoKey != labels[j].RepoKey {
			return labels[i].RepoKey < labels[j].RepoKey
		}
		return labels[i].SHA < labels[j].SHA
	})
	return labels, nil
}

func appendGitFixes(labels []label, seen map[[2]string]bool, r osvRecord, eco string, pop map[[2]string]population) []label {
	for _, a := range r.Affected {
		p, ok := pop[[2]string{eco, strings.ToLower(a.Name)}]
		if !ok {
			continue
		}
		key := repoKey(p.Repo)
		for _, rg := range a.Ranges {
			if rg.Type != "GIT" {
				continue
			}
			for _, ev := range rg.Events {
				if !shaRE.MatchString(ev.Fixed) || seen[[2]string{key, ev.Fixed}] {
					continue
				}
				seen[[2]string{key, ev.Fixed}] = true
				labels = append(labels, label{
					SHA: ev.Fixed, Repo: p.Repo, RepoKey: key,
					Class: "advised", Source: r.ID, OSVRepo: rg.Repo,
				})
			}
		}
	}
	return labels
}

func readOSV(path string) ([]osvRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []osvRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, scannerBuf), maxLogRecord)
	for sc.Scan() {
		var r osvRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// readCommitLog parses the corpus commit dump: 0x1e-terminated records of
// 0x1f-separated SHA, author date, author name, subject, body. Commit text is
// attacker-controlled; records are length-capped and malformed ones skipped.
func readCommitLog(path string) ([]logRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseCommitLog(io.LimitReader(f, maxLogBytes))
}

func parseCommitLog(r io.Reader) ([]logRecord, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, scannerBuf), maxLogRecord)
	sc.Split(splitRecord)
	var out []logRecord
	for sc.Scan() {
		f := bytes.SplitN(sc.Bytes(), []byte{fieldSep}, logFields)
		if len(f) != logFields || !shaRE.Match(bytes.TrimSpace(f[0])) {
			continue
		}
		out = append(out, logRecord{
			SHA:     string(bytes.TrimSpace(f[0])),
			Date:    string(f[1]),
			Author:  string(f[2]),
			Subject: string(f[3]),
			Body:    string(f[4]),
		})
	}
	if err := sc.Err(); errors.Is(err, bufio.ErrTooLong) {
		return out, nil
	}
	return out, sc.Err()
}

func splitRecord(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, recordSep); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func loadPatterns(skillsDir string) ([]pattern, error) {
	script := filepath.Join(skillsDir, "history", "scripts", "history_candidates.py")
	out, err := exec.Command("python3", script, "patterns").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("history_candidates.py patterns: %s", bytes.TrimSpace(ee.Stderr))
		}
		return nil, err
	}
	var pats []pattern
	if err := json.Unmarshal(out, &pats); err != nil {
		return nil, err
	}
	for i := range pats {
		re, err := compilePattern(pats[i])
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", pats[i].Label, err)
		}
		pats[i].re = re
	}
	return pats, nil
}

// compilePattern maps the subset of Python re flags the history pre-filter
// uses onto RE2 inline flags. The patterns avoid backreferences and
// lookaround, so RE2 accepts them unchanged.
func compilePattern(p pattern) (*regexp.Regexp, error) {
	var fl string
	if p.Flags&2 != 0 { // re.IGNORECASE
		fl += "i"
	}
	if p.Flags&16 != 0 { // re.DOTALL
		fl += "s"
	}
	src := p.Pattern
	if fl != "" {
		src = "(?" + fl + ")" + src
	}
	return regexp.Compile(src)
}

func scorePrefilter(dataDir string, labels []label, pats []pattern) ([]prefilterRow, error) {
	byRepo := map[string][]label{}
	for _, l := range labels {
		byRepo[l.RepoKey] = append(byRepo[l.RepoKey], l)
	}
	keys := make([]string, 0, len(byRepo))
	for k := range byRepo {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rows []prefilterRow
	for _, key := range keys {
		recs, err := readCommitLog(filepath.Join(dataDir, "commits", key+".log"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		idx := map[string]logRecord{}
		for _, r := range recs {
			idx[r.SHA] = r
		}
		for _, l := range byRepo[key] {
			row := prefilterRow{label: l}
			if rec, ok := idx[l.SHA]; ok {
				row.InLog = true
				row.Subject = rec.Subject
				row.Terms = matchTerms(rec.Subject+"\n"+rec.Body, pats)
				row.Matched = len(row.Terms) > 0
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func matchTerms(msg string, pats []pattern) []string {
	var terms []string
	for _, p := range pats {
		if p.re.MatchString(msg) {
			terms = append(terms, p.Label)
		}
	}
	return terms
}

type agg struct{ total, inLog, matched int }

func summarise(w io.Writer, rows []prefilterRow, pats []pattern) error {
	byClass := map[string]*agg{}
	hits := map[string]map[string]int{}
	for _, r := range rows {
		a := byClass[r.Class]
		if a == nil {
			a = &agg{}
			byClass[r.Class] = a
		}
		a.total++
		if r.InLog {
			a.inLog++
		}
		if r.Matched {
			a.matched++
		}
		for _, t := range r.Terms {
			if hits[r.Class] == nil {
				hits[r.Class] = map[string]int{}
			}
			hits[r.Class][t]++
		}
	}
	classes := make([]string, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		a := byClass[c]
		recall := 0.0
		if a.inLog > 0 {
			recall = float64(a.matched) / float64(a.inLog)
		}
		if _, err := fmt.Fprintf(w, "%-10s total=%d in_log=%d matched=%d recall(in_log)=%.3f\n",
			c, a.total, a.inLog, a.matched, recall); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintln(w)
	for _, p := range pats {
		name := p.Label
		if p.Ecosystem != "" {
			name = p.Label + " [" + p.Ecosystem + "]"
		}
		if _, err := fmt.Fprintf(w, "%-32s", name); err != nil {
			return err
		}
		for _, c := range classes {
			if _, err := fmt.Fprintf(w, "  %s=%d", c, hits[c][p.Label]); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	return nil
}

func readLabels(out *os.Root) ([]label, error) {
	f, err := out.Open("labels.jsonl")
	if err != nil {
		return nil, fmt.Errorf("read labels (run -mode labels first): %w", err)
	}
	defer func() { _ = f.Close() }()
	var labels []label
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, scannerBuf), maxLogRecord)
	for sc.Scan() {
		var l label
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, err
		}
		labels = append(labels, l)
	}
	return labels, sc.Err()
}

func writeJSONL[T any](out *os.Root, name string, rows []T) error {
	f, err := out.Create(name)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			_ = f.Close()
			return err
		}
	}
	return f.Close()
}
