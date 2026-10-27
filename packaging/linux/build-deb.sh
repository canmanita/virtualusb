#!/bin/bash
# Builds dist/vhserver_<version>_all.deb. Pure Python, so one package serves amd64, arm64 and armhf (Raspberry Pi).
# Run on any Linux or in WSL:  bash packaging/linux/build-deb.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VERSION="$(sed -n 's/^__version__ = "\(.*\)".*/\1/p' "$ROOT/vhserver/__init__.py")"
[ -n "$VERSION" ] || { echo "cannot read the version" >&2; exit 1; }
OUT="$ROOT/dist"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

install -d -m 0755 "$STAGE/DEBIAN" "$STAGE/usr/lib/vhserver/vhserver" "$STAGE/usr/bin" \
    "$STAGE/lib/systemd/system" "$STAGE/lib/udev/rules.d" "$STAGE/etc/vhserver" \
    "$STAGE/etc/ufw/applications.d" "$STAGE/usr/share/doc/vhserver"

# application code
for file in "$ROOT"/vhserver/*.py; do
    install -m 0644 "$file" "$STAGE/usr/lib/vhserver/vhserver/"
done

# -I: isolated mode (no current directory, no PYTHONPATH, no user site), so a file planted in the directory the
# administrator runs this from can never be imported as root; the package path is added explicitly.
cat > "$STAGE/usr/bin/vhserver" <<'WRAPPER'
#!/bin/sh
exec python3 -I -c 'import sys; sys.path.insert(0, "/usr/lib/vhserver"); from vhserver.__main__ import main; main()' "$@"
WRAPPER
chmod 0755 "$STAGE/usr/bin/vhserver"

tr -d '\r' < "$HERE/vhserver.service" > "$STAGE/lib/systemd/system/vhserver.service"
tr -d '\r' < "$HERE/70-vhserver.rules" > "$STAGE/lib/udev/rules.d/70-vhserver.rules"
tr -d '\r' < "$HERE/ufw-vhserver" > "$STAGE/etc/ufw/applications.d/vhserver"
tr -d '\r' < "$HERE/config.json" > "$STAGE/etc/vhserver/config.json"
install -m 0644 "$ROOT/README.md" "$STAGE/usr/share/doc/vhserver/README.md"
install -m 0644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/vhserver/LICENSE"
for doc in LINUX-INSTALL.md RASPBERRY-PI.md SECURITY.md config.example.json; do
    install -m 0644 "$ROOT/docs/$doc" "$STAGE/usr/share/doc/vhserver/$doc"
done
chmod 0644 "$STAGE/lib/systemd/system/vhserver.service" "$STAGE/lib/udev/rules.d/70-vhserver.rules" \
    "$STAGE/etc/ufw/applications.d/vhserver" "$STAGE/etc/vhserver/config.json"

for script in postinst prerm postrm; do
    tr -d '\r' < "$HERE/$script" > "$STAGE/DEBIAN/$script"
    chmod 0755 "$STAGE/DEBIAN/$script"
done
printf '/etc/vhserver/config.json\n/etc/ufw/applications.d/vhserver\n' > "$STAGE/DEBIAN/conffiles"

cat > "$STAGE/usr/share/doc/vhserver/copyright" <<COPYRIGHT
VirtualUSB is an independent implementation of a USB-over-network wire protocol, written for interoperability.
It contains no code from any third-party product.
COPYRIGHT

SIZE="$(du -sk "$STAGE" | cut -f1)"
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: vhserver
Version: $VERSION
Section: utils
Priority: optional
Architecture: all
Installed-Size: $SIZE
Depends: python3 (>= 3.9), python3-usb1, python3-zeroconf, python3-ifaddr, python3-lz4, libusb-1.0-0, udev, acl, adduser
Recommends: python3-cryptography
Suggests: ufw
Maintainer: vhserver <root@localhost>
Description: VirtualUSB USB-over-network server
 Shares the USB devices plugged into this machine over the local network. Devices are
 detected on hot-plug and can be used from a compatible client, which finds the
 server automatically (mDNS). Runs as an unprivileged systemd service.
CONTROL

mkdir -p "$OUT"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT/vhserver_${VERSION}_all.deb" >/dev/null
( cd "$OUT" && sha256sum "vhserver_${VERSION}_all.deb" > "vhserver_${VERSION}_all.deb.sha256" )
echo "built $OUT/vhserver_${VERSION}_all.deb"
