#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)   # repo root
LOGDIR="$ROOT/forum-app/logs"
mkdir -p "$LOGDIR"

echo "▶ 1) start proxy"
(cd "$ROOT/origo/proxy" && go run main.go -listen \
     >"$LOGDIR/proxy.out" 2>&1 & echo $! >"$LOGDIR/proxy.pid")

echo "▶ 2) client → TLS request (through proxy)"
(cd "$ROOT/origo/client" && go run main.go -request)

echo "▶ 3) client → post‑process handshake"
(cd "$ROOT/origo/client" && go run main.go -postprocess-kdc)

echo "▶ 4) client → post‑process record"
(cd "$ROOT/origo/client" && go run main.go -postprocess-record)

echo "▶ 5) proxy → confirm public inputs"
(cd "$ROOT/origo/proxy" && go run main.go -postprocess)

echo "▶ 6) proxy → ZK setup (only needed once)"
if [ ! -f "$ROOT/proxy/keys/vk" ]; then
  (cd "$ROOT/origo/proxy" && go run main.go -debug -setup)
fi

echo "▶ 7) client → prove"
(cd "$ROOT/origo/client" && go run main.go -prove)

echo "▶ 8) proxy → verify"
(cd "$ROOT/origo/proxy" && go run main.go -debug -verify)

echo "▶ 9) proxy → stats"
(cd "$ROOT/origo/proxy" && go run main.go -debug -stats)

echo "✅  complete"

# Clean‑up
kill "$(cat "$LOGDIR/proxy.pid")"
rm "$LOGDIR/proxy.pid"