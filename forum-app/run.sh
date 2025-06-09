#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/jaysheelpandya/sp-2025-oracle-project"  # repo root
LOGDIR="$ROOT/forum-app/logs"
mkdir -p "$LOGDIR"

echo "0) cleanup previous local storage"
(cd "$ROOT/origo/client/local_storage" && rm -f *.json 2>/dev/null || true)
(cd "$ROOT/origo/proxy/local_storage" && rm -f *.* 2>/dev/null || true)
sleep 1

echo "1) start proxy"
(cd "$ROOT/origo/proxy" && go run main.go -listen \
     >"$LOGDIR/proxy.out" 2>&1 & echo $! >"$LOGDIR/proxy.pid")
sleep 2
echo "PID of proxy listener is $(cat "$LOGDIR/proxy.pid")"
sleep 1

echo "2) client → TLS request (through proxy)"
(cd "$ROOT/origo/client" && go run main.go -request)

echo "3) client → post‑process handshake"
(cd "$ROOT/origo/client" && go run main.go -postprocess-kdc)

echo "4) client → post‑process record"
(cd "$ROOT/origo/client" && go run main.go -postprocess-record)

echo "5) proxy → confirm public inputs"
(cd "$ROOT/origo/proxy" && go run main.go -postprocess)

echo "6) proxy → ZK setup (only needed once)"
if [ ! -f "$ROOT/proxy/keys/vk" ]; then
(cd "$ROOT/origo/proxy" && go run main.go -debug -setup)
fi

echo "7) client → prove"
(cd "$ROOT/origo/client" && go run main.go -prove)

echo "8) proxy → verify"
(cd "$ROOT/origo/proxy" && go run main.go -debug -verify)

echo "▶ 9) proxy → stats"
(cd "$ROOT/origo/proxy" && go run main.go -debug -stats)

echo "Successfully completed."

# Clean‑up
(cd "$ROOT/origo/client/local_storage" && rm -f *.json 2>/dev/null || true)
(cd "$ROOT/origo/proxy/local_storage" && rm -f *.* 2>/dev/null || true)
