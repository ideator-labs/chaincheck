// chaincheck finds the registry hosts your build files pull from or push to,
// fetches each host's TLS chain, and fails if any certificate in the chain
// (or any issuer named by one) is on a blocklist of intermediate CAs.
package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Ref is one image or registry reference found in a build file.
type Ref struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"ref"`
	Host string `json:"host"`
}

// Cert is one certificate the host served.
type Cert struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	SHA256  string `json:"sha256"`
}

// Verdict is the result for one host.
type Verdict string

const (
	Blocked     Verdict = "BLOCKED"
	Clean       Verdict = "CLEAN"
	Unreachable Verdict = "UNREACHABLE"
	Skipped     Verdict = "SKIPPED"
)

// HostResult is what chaincheck reports per registry host.
type HostResult struct {
	Host    string   `json:"host"`
	Verdict Verdict  `json:"verdict"`
	Matches []string `json:"matches,omitempty"`
	Chain   []Cert   `json:"chain,omitempty"`
	Error   string   `json:"error,omitempty"`
	Refs    []Ref    `json:"refs"`
}

var (
	fromRe    = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--\S+\s+)*(\S+)`)
	imageRe   = regexp.MustCompile(`^\s*"?image"?\s*:\s*["']?([^"'\s,]+)`)
	dockerCLI = regexp.MustCompile(`docker\s+(?:login|pull|push)\s+(?:-\S+\s+(?:\S+\s+)?)*([A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s"']*)?)`)
)

// isBuildFile says which files are scanned and how.
func isBuildFile(rel string) bool {
	base := filepath.Base(rel)
	switch {
	case strings.HasPrefix(base, "Dockerfile"), strings.HasSuffix(base, ".Dockerfile"), strings.HasPrefix(base, "Containerfile"):
		return true
	case strings.Contains(base, "compose") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
		return true
	case base == "devcontainer.json" || base == ".devcontainer.json":
		return true
	case strings.Contains(filepath.ToSlash(rel), ".github/workflows/") || strings.Contains(base, "gitlab-ci"):
		return true
	}
	return false
}

// registryHost applies the Docker reference rule: the first path part is a
// registry host only if it has a dot or a port, or is "localhost".
func registryHost(ref string) string {
	if i := strings.IndexAny(ref, "$"); i == 0 {
		return ""
	}
	first, _, hasSlash := strings.Cut(ref, "/")
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return strings.ToLower(first)
	}
	if !hasSlash && strings.Contains(strings.Split(first, ":")[0], ".") && !strings.Contains(first, "@") {
		return strings.ToLower(first) // bare host, e.g. "docker login ghcr.io:443"
	}
	return "docker.io"
}

func scan(root string) ([]Ref, error) {
	var refs []Ref
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if !isBuildFile(rel) {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		n := 0
		stages := map[string]bool{}
		for s.Scan() {
			n++
			line := s.Text()
			var found []string
			if m := fromRe.FindStringSubmatch(line); m != nil && strings.HasPrefix(filepath.Base(rel), "Dockerfile") {
				found = append(found, m[1])
				if as := regexp.MustCompile(`(?i)\sAS\s+(\S+)`).FindStringSubmatch(line); as != nil {
					stages[strings.ToLower(as[1])] = true
				}
			}
			if m := imageRe.FindStringSubmatch(line); m != nil {
				found = append(found, m[1])
			}
			for _, m := range dockerCLI.FindAllStringSubmatch(line, -1) {
				found = append(found, m[1])
			}
			for _, r := range found {
				if stages[strings.ToLower(r)] || r == "scratch" {
					continue
				}
				h := registryHost(r)
				if h == "" {
					continue
				}
				refs = append(refs, Ref{File: filepath.ToSlash(rel), Line: n, Text: r, Host: h})
			}
		}
		return s.Err()
	})
	return refs, err
}

func loadBlocklist(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out[l] = true
		}
	}
	return out, nil
}

// fetchChain returns the certificates the host serves. Verification is
// skipped on purpose: we want to read the chain even when it would fail.
func fetchChain(host string, resolve map[string]string) ([]Cert, error) {
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	sni, _, _ := net.SplitHostPort(addr)
	if r, ok := resolve[addr]; ok {
		addr = r
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var chain []Cert
	for _, c := range conn.ConnectionState().PeerCertificates {
		sum := sha256.Sum256(c.Raw)
		chain = append(chain, Cert{Subject: c.Subject.CommonName, Issuer: c.Issuer.CommonName, SHA256: hex.EncodeToString(sum[:])})
	}
	return chain, nil
}

// match lists blocklisted names in the chain. A served intermediate matches
// by subject; an issuer name catches a blocked CA the server did not send.
// leafOnly is the naive check (look at the leaf subject only), kept for --break.
func match(chain []Cert, block map[string]bool, leafOnly bool) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name, why string) {
		if block[name] && !seen[name] {
			seen[name] = true
			out = append(out, name+" ("+why+")")
		}
	}
	for i, c := range chain {
		if leafOnly && i > 0 {
			break
		}
		add(c.Subject, "served")
		if !leafOnly {
			add(c.Issuer, "issuer of "+c.Subject)
		}
	}
	return out
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	var resolves, skips multi
	blockPath := flag.String("blocklist", "blocklist.txt", "file of blocked CA common names")
	asJSON := flag.Bool("json", false, "print JSON")
	leafOnly := flag.Bool("leaf-only", false, "naive mode: only check the leaf certificate (used by demo --break)")
	flag.Var(&resolves, "resolve", "host:port=ip:port override, repeatable")
	flag.Var(&skips, "skip-host", "registry host to skip, repeatable")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: chaincheck [flags] DIR")
		os.Exit(2)
	}
	block, err := loadBlocklist(*blockPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	resolve := map[string]string{}
	for _, r := range resolves {
		k, v, _ := strings.Cut(r, "=")
		resolve[k] = v
	}
	refs, err := scan(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	byHost := map[string]*HostResult{}
	for _, r := range refs {
		if byHost[r.Host] == nil {
			byHost[r.Host] = &HostResult{Host: r.Host}
		}
		byHost[r.Host].Refs = append(byHost[r.Host].Refs, r)
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	exit := 0
	var results []HostResult
	for _, h := range hosts {
		res := byHost[h]
		switch {
		case contains(skips, h):
			res.Verdict = Skipped
		default:
			chain, err := fetchChain(h, resolve)
			if err != nil {
				res.Verdict, res.Error = Unreachable, err.Error()
				if exit == 0 {
					exit = 3
				}
			} else {
				res.Chain = chain
				res.Matches = match(chain, block, *leafOnly)
				res.Verdict = Clean
				if len(res.Matches) > 0 {
					res.Verdict = Blocked
					exit = 1
				}
			}
		}
		results = append(results, *res)
	}
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		e.Encode(results)
	} else {
		for _, r := range results {
			fmt.Printf("%-11s %s\n", r.Verdict, r.Host)
			for _, m := range r.Matches {
				fmt.Printf("            blocked CA: %s\n", m)
			}
			if r.Error != "" {
				fmt.Printf("            error: %s\n", r.Error)
			}
			for _, ref := range r.Refs {
				fmt.Printf("            %s:%d %s\n", ref.File, ref.Line, ref.Text)
			}
		}
	}
	os.Exit(exit)
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
