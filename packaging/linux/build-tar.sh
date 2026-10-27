#!/bin/bash
# Builds dist/vhserver-<version>-linux.tar.gz: code + install-generic.sh for distributions without dpkg.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VERSION="$(sed -n 's/^__version__ = "\(.*\)".*/\1/p' "$ROOT/vhserver/__init__.py")"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
NAME="vhserver-$VERSION-linux"
install -d "$STAGE/$NAME/vhserver"
for file in "$ROOT"/vhserver/*.py; do
    install -m 0644 "$file" "$STAGE/$NAME/vhserver/"
done
for file in vhserver.service 70-vhserver.rules config.json; do tr -d '\r' < "$HERE/$file" > "$STAGE/$NAME/$file"; done
tr -d '\r' < "$HERE/install-generic.sh" > "$STAGE/$NAME/install.sh"; chmod 0755 "$STAGE/$NAME/install.sh"
install -m 0644 "$ROOT/docs/LINUX-INSTALL.md" "$STAGE/$NAME/README.md"
for doc in RASPBERRY-PI.md SECURITY.md config.example.json; do
    install -m 0644 "$ROOT/docs/$doc" "$STAGE/$NAME/$doc"
done
mkdir -p "$ROOT/dist"
tar -C "$STAGE" --owner=0 --group=0 -czf "$ROOT/dist/$NAME.tar.gz" "$NAME"
( cd "$ROOT/dist" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )
echo "built $ROOT/dist/$NAME.tar.gz"
