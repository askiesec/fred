#!/usr/bin/env bash
set -e

APP="fred"
VERSION="${1:-dev}"
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
OUT="dist"

mkdir -p "$OUT"

case "$(uname -s)" in
  Linux)            OS="linux"   ;;
  Darwin)           OS="darwin"  ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  *)
    echo "unknown OS, building for all platforms"
    OS="all"
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)             ARCH="amd64" ;;
esac

LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${GIT_COMMIT} -X main.buildTime=${BUILD_TIME}"

go clean -cache

build_one() {
  local goos=$1
  local goarch=$2
  local name="$OUT/$APP"
  [ "$goos" = "windows" ] && name="${name}.exe"

  rm -f "$name"
  printf "  building %-16s" "${goos}/${goarch}..."
  GOOS=$goos GOARCH=$goarch go build -ldflags="$LDFLAGS" -o "$name" .
  echo " $name ($(du -sh "$name" | cut -f1))"
}

echo "fred $VERSION ($GIT_COMMIT)"
echo ""

if [ "$OS" = "all" ]; then
  for target in "linux amd64" "linux arm64" "darwin amd64" "darwin arm64" "windows amd64"; do
    build_one $target
  done
else
  build_one "$OS" "$ARCH"
fi

if [ $? -eq 0 ]; then
  echo ""
  echo "build successful -> dist/$APP"
  echo ""
  echo "usage:"
  echo "  ./dist/$APP --help                                       # show all flags"
  echo "  ./dist/$APP --version                                    # show version info"
  echo "  cat urls.txt | ./dist/$APP                               # basic declutter"
  echo "  cat urls.txt | ./dist/$APP -p                            # only URLs with params"
  echo "  cat urls.txt | ./dist/$APP -f json                       # json output"
  echo "  cat urls.txt | ./dist/$APP -f csv -o results.csv         # csv to file"
  echo "  cat urls.txt | ./dist/$APP --scope scope.txt             # filter by scope"
  echo "  cat urls.txt | ./dist/$APP --secrets-out secrets.txt     # flag high-entropy params"
else
  echo "build failed"
  exit 1
fi