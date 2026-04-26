// Package lists fetches and parses domain blocklists in three common
// formats (hosts, AdBlock Plus, plain domain). Every parser returns a
// deduplicated, lowercased slice of strings, with each entry validated
// against a strict domain regex before being accepted.
package lists

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	UserAgent     = "ebpf-adblocker/1.0"
	FetchTimeout  = 30 * time.Second
	MaxBodyBytes  = 64 << 20 // 64 MiB
)

// Format names what kind of list a Source contains.
type Format string

const (
	FormatHosts   Format = "hosts"
	FormatAdblock Format = "adblock"
	FormatDomain  Format = "domain"
)

// Source describes one upstream blocklist.
type Source struct {
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Format Format `yaml:"format"`
}

// domainRe accepts a lowercased ASCII domain. It enforces:
//   - 1..63 chars per label
//   - alnum/hyphen, no leading or trailing hyphen
//   - at least one dot (TLD-only entries are rejected)
//   - 1..253 total length
var domainRe = regexp.MustCompile(
	`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}[a-z0-9]?$`,
)

// hostsRe captures the domain in a /etc/hosts-style sinkhole line.
// It deliberately allows uppercase in the source - we lowercase later.
var hostsRe = regexp.MustCompile(
	`^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([A-Za-z0-9._-]+)`,
)

// adblockRe captures the domain in an EasyList-style filter:  ||domain^
var adblockRe = regexp.MustCompile(
	`^\|\|([A-Za-z0-9._-]+)\^?`,
)

var hostsSkip = map[string]struct{}{
	"localhost":      {},
	"localhost.localdomain": {},
	"local":          {},
	"broadcasthost":  {},
	"ip6-localhost":  {},
	"ip6-loopback":   {},
}

// ValidDomain reports whether s passes the strict regex check after
// lowercasing. Exported so callers (e.g. the CLI's `block` command)
// can reject bad input the same way.
func ValidDomain(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 253 {
		return false
	}
	if _, skip := hostsSkip[s]; skip {
		return false
	}
	return domainRe.MatchString(s)
}

// ParseHosts parses an /etc/hosts-style sinkhole list.
func ParseHosts(r io.Reader) ([]string, error) {
	return scan(r, func(line string) (string, bool) {
		m := hostsRe.FindStringSubmatch(line)
		if m == nil {
			return "", false
		}
		return m[1], true
	})
}

// ParseAdblock parses an EasyList / AdBlock Plus filter list, keeping
// only the network-level rules of the form `||domain^`.
func ParseAdblock(r io.Reader) ([]string, error) {
	return scan(r, func(line string) (string, bool) {
		t := strings.TrimSpace(line)
		if t == "" {
			return "", false
		}
		switch t[0] {
		case '!', '[':
			return "", false
		}
		if strings.HasPrefix(t, "@@") || strings.HasPrefix(t, "##") {
			return "", false
		}
		m := adblockRe.FindStringSubmatch(t)
		if m == nil {
			return "", false
		}
		return m[1], true
	})
}

// ParseDomain parses a list of plain domains, one per line, with `#`
// comments allowed both at start of line and inline.
func ParseDomain(r io.Reader) ([]string, error) {
	return scan(r, func(line string) (string, bool) {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		t := strings.TrimSpace(line)
		if t == "" {
			return "", false
		}
		return t, true
	})
}

// scan is the shared body for the three parsers. It runs the per-line
// extractor, validates the result, then dedupes and sorts the output
// for stable iteration order.
func scan(r io.Reader, extract func(string) (string, bool)) ([]string, error) {
	seen := make(map[string]struct{}, 1024)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		raw, ok := extract(sc.Text())
		if !ok {
			continue
		}
		d := strings.ToLower(strings.TrimSpace(raw))
		d = strings.TrimSuffix(d, ".")
		if !ValidDomain(d) {
			continue
		}
		seen[d] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// Parse selects a parser by Source.Format.
func Parse(format Format, r io.Reader) ([]string, error) {
	switch format {
	case FormatHosts:
		return ParseHosts(r)
	case FormatAdblock:
		return ParseAdblock(r)
	case FormatDomain:
		return ParseDomain(r)
	default:
		return nil, fmt.Errorf("unknown list format: %q", format)
	}
}

// Fetch downloads a single source, with a 30s timeout and a 64 MiB
// body cap.
func Fetch(ctx context.Context, src Source) ([]string, error) {
	c, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(c, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src.Name, err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", src.Name, resp.StatusCode)
	}
	body := io.LimitReader(resp.Body, MaxBodyBytes)
	return Parse(src.Format, body)
}

// FetchAll fetches every source in `srcs` and returns the deduplicated
// union of every domain found. Errors from individual sources are
// returned aggregated; callers may choose to log and continue.
func FetchAll(ctx context.Context, srcs []Source) ([]string, []error) {
	merged := make(map[string]struct{}, 1<<16)
	var errs []error
	for _, s := range srcs {
		ds, err := Fetch(ctx, s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, d := range ds {
			merged[d] = struct{}{}
		}
	}
	out := make([]string, 0, len(merged))
	for d := range merged {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, errs
}
