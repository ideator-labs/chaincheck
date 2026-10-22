# ChainCheck

Find the container registries your build files use whose TLS chain runs through one of the eight revoked eMudhra intermediates. Docker Engine 29.9.2 (Go 1.26.10) rejects those chains, so pulls and pushes fail with an x509 error after the upgrade. Run ChainCheck before you roll the new engine to CI runners.

It reads Dockerfiles, compose files, devcontainer.json and CI workflows, works out each registry host the Docker way, fetches the host's certificate chain, and fails if any served certificate or any issuer name matches `blocklist.txt`.

```
go run . path/to/repo          # exit 1 if a host is blocked, 3 if one is unreachable
go run . --json path/to/repo
```

Run the self-checking demo with `bash demo.sh` (Go 1.22+ and openssl, no network). `bash demo.sh --break` switches to a naive leaf-only check and fails.

The demo registries are local stand-ins: a private test root signs an intermediate that only copies the blocked name `EM DV TLS CA - G3B`. They are not eMudhra certificates.

For status, design, limits and next steps, read [AGENTS.md](AGENTS.md).

Source for the blocked list: [Docker Engine 29 release notes, 29.9.2](https://docs.docker.com/engine/release-notes/29).
