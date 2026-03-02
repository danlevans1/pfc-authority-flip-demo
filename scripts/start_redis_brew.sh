#!/usr/bin/env bash
set -euo pipefail

if ! command -v brew >/dev/null 2>&1; then
  echo "FAIL: Homebrew is not installed." >&2
  exit 1
fi

if ! brew ls --versions redis >/dev/null 2>&1; then
  echo "Installing redis via Homebrew..."
  brew install redis
fi

brew tap homebrew/services >/dev/null 2>&1 || true
brew services start redis

if command -v redis-cli >/dev/null 2>&1; then
  if redis-cli ping | grep -qx 'PONG'; then
    echo "PASS: redis-cli ping => PONG"
    exit 0
  fi
fi

echo "FAIL: Redis did not respond with PONG on localhost:6379" >&2
exit 1
