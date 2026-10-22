#!/usr/bin/env bash
# ChainCheck demo. Needs Go 1.22+ and openssl. Runs fully local.
# --break runs the scanner in naive leaf-only mode, which should fail checks.
set -u
cd "$(dirname "$0")"
MODE=normal; [ "${1:-}" = "--break" ] && MODE=break
WORK=$(mktemp -d); trap 'kill $SPID 2>/dev/null; rm -rf "$WORK"' EXIT
go build -o "$WORK/chaincheck" . && go build -o "$WORK/standin" ./cmd/standin || exit 2
"$WORK/standin" -out "$WORK/pem" > "$WORK/standin.log" 2>&1 & SPID=$!
for _ in $(seq 50); do grep -q ready "$WORK/standin.log" && break; sleep 0.1; done
EXTRA=(); [ $MODE = break ] && EXTRA=(--leaf-only)
run() { "$WORK/chaincheck" --blocklist blocklist.txt \
  --resolve registry-bad.test:5443=127.0.0.1:15443 \
  --resolve registry-good.test:5444=127.0.0.1:15444 \
  --skip-host docker.io "${EXTRA[@]}" "$@"; }
run fixtures/repo; CODE=$?
run --json fixtures/repo > "$WORK/out.json"
echo
pass=0; fail=0
check() { if eval "$2"; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }
J() { python3 -c "import json,sys;d=json.load(open('$WORK/out.json'));print($1)"; }
check "1 both stand-in chains are valid X.509 chains to the test root (openssl verify)" \
  "openssl verify -CAfile $WORK/pem/root.pem -untrusted <(sed -n '/END/,\$p' $WORK/pem/bad-chain.pem | tail -n +2) <(sed -n '1,/END/p' $WORK/pem/bad-chain.pem) >/dev/null 2>&1 && openssl verify -CAfile $WORK/pem/root.pem -untrusted <(sed -n '/END/,\$p' $WORK/pem/good-chain.pem | tail -n +2) <(sed -n '1,/END/p' $WORK/pem/good-chain.pem) >/dev/null 2>&1"
check "2 found 3 hosts from 4 kinds of build file (Dockerfile, compose, CI, devcontainer)" \
  "[ \"\$(J 'len(d)')\" = 3 ] && [ \"\$(J 'len({x[\"file\"] for r in d for x in r[\"refs\"]})')\" = 4 ]"
check "3 registry-bad.test:5443 is BLOCKED by 'EM DV TLS CA - G3B'" \
  "[ \"\$(J '[r for r in d if r[\"host\"]==\"registry-bad.test:5443\"][0][\"verdict\"]')\" = BLOCKED ] && J 'd' | grep -q 'EM DV TLS CA - G3B'"
check "4 every file and line that uses the bad host is listed (4 refs in 3 files)" \
  "[ \"\$(J 'len([r for r in d if r[\"host\"]==\"registry-bad.test:5443\"][0][\"refs\"])')\" = 4 ] && [ \"\$(J 'len({x[\"file\"] for x in [r for r in d if r[\"host\"]==\"registry-bad.test:5443\"][0][\"refs\"]})')\" = 3 ]"
check "5 registry-good.test:5444 is CLEAN and includes the docker login line (ci.yml:9)" \
  "[ \"\$(J '[r for r in d if r[\"host\"]==\"registry-good.test:5444\"][0][\"verdict\"]')\" = CLEAN ] && [ \"\$(J '[(x[\"file\"],x[\"line\"]) for r in d if r[\"host\"]==\"registry-good.test:5444\" for x in r[\"refs\"]].count((\".github/workflows/ci.yml\",9))')\" = 1 ]"
check "6 exit code is 1 so CI fails" "[ $CODE = 1 ]"
# 7: a server that sends only its leaf still gets caught through the issuer name.
check "7 blocked CA caught by issuer name even when the intermediate is not served" \
  "go run ./cmd/leafcheck $WORK/pem/bad-chain.pem blocklist.txt ${EXTRA[*]}"
echo; echo "$pass passed, $fail failed"
[ $fail = 0 ]
