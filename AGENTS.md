# AGENTS.md: ChainCheck

## What this is and the claim
A Go CLI, standard library only. Claim: given a repo, it lists every registry host referenced in build files, reads each host's served TLS chain, and fails (exit 1) when the chain contains or is issued by a CA named in `blocklist.txt`. The shipped list holds the eight eMudhra intermediates that Docker Engine 29.9.2 rejects (CVE-2026-111943).

## Status: real vs stubbed
- Real: file scanning, Docker host parsing, TLS handshake and chain read, name matching, exit codes, JSON output. A manual run against ghcr.io, quay.io and public.ecr.aws on 2026-10-22 returned CLEAN for all three.
- Stand-in: `cmd/standin` serves two local TLS endpoints. Its "bad" intermediate is self-made and only reuses the name `EM DV TLS CA - G3B`. No real eMudhra-chained registry was used.
- `cmd/leafcheck` simulates a server that sends only its leaf, to prove the issuer-name rule.

## Data shape
`Ref{file, line, ref, host}` per reference. Grouped into `HostResult{host, verdict, matches[], chain[]Cert{subject, issuer, sha256}, error, refs[]}`. Verdict is one of BLOCKED, CLEAN, UNREACHABLE, SKIPPED. Exit: 0 clean, 1 any BLOCKED, 3 any UNREACHABLE without BLOCKED, 2 usage error.

## Repo map
- `main.go`: scanner, host rule, TLS fetch, matcher, CLI.
- `blocklist.txt`: blocked CA common names with source.
- `cmd/standin`: test root, two intermediates, two leaves, TLS on 127.0.0.1:15443 (bad) and :15444 (good).
- `cmd/leafcheck`: issuer-only check on one PEM.
- `fixtures/repo`: Dockerfile, compose.yaml, .github/workflows/ci.yml, .devcontainer/devcontainer.json.
- `demo.sh`: builds, starts the stand-in, runs 7 checks.

## Setup, run, verify (fresh clone)
```
git clone https://github.com/ideator-labs/chaincheck && cd chaincheck
bash demo.sh          # expect "7 passed, 0 failed", exit 0
bash demo.sh --break  # expect checks 3, 6, 7 to FAIL, exit 1
```
Needs Go 1.22+, openssl, python3 (the demo parses JSON with it). No network.

## Design decisions
- Match by subject and issuer common name, because the release notes publish names, not fingerprints. Issuer matching catches servers that do not send the intermediate.
- Handshake with verification off, so a chain that would fail can still be read.
- Host rule follows Docker references: first path part is a host only if it has a dot, a port, or is `localhost`; otherwise docker.io. Bare `docker login host:port` is a host.
- Multi-stage names (`FROM build`) and `scratch` are not hosts.
- `--resolve host:port=ip:port` lets the demo point fixture hosts at the stand-in while keeping the real SNI.

## Limits
- Name matching can false-positive on a private CA that reuses a blocked name, and misses a renamed cert. Fingerprints would be stronger.
- Does not read registry mirrors in daemon.json, `buildx` bake files, Kubernetes manifests, Helm values, or variables like `${REGISTRY}`.
- CI parsing is regex, not YAML; refs with spaces (for example `${{ github.sha }}`) are cut at the space.
- Does not build the full path to a root, so a blocked CA above the first issuer and not served is missed.
- One handshake per host; a load balancer serving different chains per node can hide a bad one.

## Next steps (done when)
1. Fingerprint list: accept `sha256:` lines and match on cert hash. Done when a test fixture with a renamed blocked cert is caught by hash.
2. Build the full path with `x509.Verify` against the system pool plus served intermediates and check every element. Done when an unsent grandparent CA is flagged.
3. Read `/etc/docker/daemon.json` registry-mirrors and bake files. Done when fixtures with a mirror host show up as refs.
4. GitHub Action wrapper. Done when a workflow in this repo fails on the bad fixture.
5. Variable expansion from `.env` and `ARG` defaults. Done when `FROM ${REGISTRY}/x` resolves in a fixture.

## Working rules
- Commit as danielgerlag <daniel@gerlag.ca>.
- Keep `bash demo.sh` green and `--break` red before pushing.
- Never claim a stand-in cert is real eMudhra. No em-dashes in docs.

## Sources
- Docker Engine 29.9.2 release notes: https://docs.docker.com/engine/release-notes/29
