#!/bin/sh
# Installer for distributions without a .deb: Python virtualenv in /opt/vhserver + the same systemd unit and udev rule.
# Needs: root, python3 (>= 3.9) with venv, the system libusb-1.0 library (libusb-1.0-0 / libusb1) and acl (setfacl).
set -eu
umask 022
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
# this script installs files from its own directory as root: refuse a directory other users can modify
if [ "$(stat -c %u "$HERE")" != 0 ] || [ -n "$(find "$HERE" -maxdepth 0 -perm /022)" ]; then
    echo "extract the archive into a root-owned, not group/world-writable directory (for example /root)" >&2
    exit 1
fi
PREFIX=/opt/vhserver

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v setfacl >/dev/null || { echo "install the 'acl' package first" >&2; exit 1; }

id vhserver >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin vhserver

install -d -m 0755 "$PREFIX" /etc/vhserver
rm -rf "$PREFIX/vhserver"
cp -r "$HERE/vhserver" "$PREFIX/vhserver"
python3 -m venv "$PREFIX/venv"
# wheels only: no setup.py of a downloaded source package ever runs as root
"$PREFIX/venv/bin/pip" install --quiet --only-binary=:all: --upgrade "libusb1>=3.0" "zeroconf>=0.130" "ifaddr"
"$PREFIX/venv/bin/pip" install --quiet --only-binary=:all: cryptography ||
    echo "cryptography not installed: 'vhserver tls enable' will not be able to create certificates"
"$PREFIX/venv/bin/pip" install --quiet --only-binary=:all: lz4 || echo "lz4 not installed: the slower pure Python decoder will be used"

cat > /usr/local/bin/vhserver <<WRAPPER
#!/bin/sh
exec $PREFIX/venv/bin/python -I -c 'import sys; sys.path.insert(0, "$PREFIX"); from vhserver.__main__ import main; main()' "\$@"
WRAPPER
chmod 0755 /usr/local/bin/vhserver
[ -f /etc/vhserver/config.json ] || install -m 0644 "$HERE/config.json" /etc/vhserver/config.json

sed 's|/usr/bin/vhserver|/usr/local/bin/vhserver|' "$HERE/vhserver.service" > /etc/systemd/system/vhserver.service
cp "$HERE/70-vhserver.rules" /etc/udev/rules.d/70-vhserver.rules
udevadm control --reload-rules && udevadm trigger --subsystem-match=usb --action=change || true
systemctl daemon-reload
systemctl enable --now vhserver.service
echo "installed. Check it with: vhserver doctor"
