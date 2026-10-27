# VirtualUSB

VirtualUSB shares the USB devices plugged into one machine over the local network, and any computer running the
free, stock **VirtualHere client** can use them as if they were plugged in locally. Devices are detected
automatically (hot-plug), announced over the network via mDNS Auto-Find, and mounted on the client with one click.

It is an independent, clean-room implementation of the wire protocol observed between the official VirtualHere
client and server (see [docs/PROTOCOL.md](docs/PROTOCOL.md)) — no code, licence checks, or binaries from the
original product are reused, reproduced, or bypassed. Written in Python, with the help of AI pair-programming.

Get the VirtualHere client (required on the computer that will *use* the shared devices) here:
**https://www.virtualhere.com/usb_client_software**

> **Disclaimer**: VirtualUSB is an independent, unofficial project. "VirtualHere" is a trademark of its
> respective owner. VirtualUSB is not affiliated with, sponsored by, or endorsed by VirtualHere or its
> maker, and is not a replacement for a paid VirtualHere license — it implements no licence checks of the
> original product, and bypasses none.

## Status

| feature | state |
|---|---|
| handshake, device list, bind/unbind, control + bulk + interrupt transfers | working, verified with client 6.0.3 |
| mDNS Auto-Find (`_vhusb._tcp`) | working |
| hot-plug add/remove, surprise removal while in use | working |
| libusb backend (Linux, Windows with WinUSB devices) | verified on Windows and on real Raspberry Pi 4 hardware (USB mass storage) |
| device passwords, nicknames, SSL (TLS) port with private CA, `_ssl_vhusb._tcp` announcement | working, verified with client 6.0.3 ([docs/SECURITY.md](docs/SECURITY.md)) |
| Windows driver auto-binding (the stock server installs WinUSB per device) | working (`--windows-bind`, administrator) |

## Installing

### Windows

Download `VHServer-Setup-<version>.exe` from [Releases](../../releases), run it, and follow the wizard
(Italian/English). It installs under `C:\ProgramData\VHServer`, opens the firewall for the local subnet (and
Tailscale, if present), registers a boot task running as SYSTEM, and starts the service immediately.

* `vhserver.exe doctor` explains why a client cannot see the server.
* `vhserver.exe uninstall` restores original drivers and removes everything.
* The installer is not code-signed, so Windows SmartScreen will warn on first run — click "More info" ->
  "Run anyway".

Details: [docs/WINDOWS-INSTALL.md](docs/WINDOWS-INSTALL.md).

### Linux (desktop, server, Raspberry Pi, any architecture)

Download `vhserver_<version>_all.deb` from [Releases](../../releases) and install it:

```
sudo apt install ./vhserver_<version>_all.deb
```

It is pure Python, so the same `.deb` works on amd64, arm64 and armhf (Raspberry Pi OS, Debian, Ubuntu). It creates
an unprivileged `vhserver` user, a hardened systemd service, a udev ACL rule for `/dev/bus/usb`, and
`/etc/vhserver/config.json`. Run `vhserver doctor` afterwards to check the setup.

For distributions without `.deb` support, download `vhserver-<version>-linux.tar.gz` instead and run its
`install.sh`.

A USB device that carries the server's own default network route (onboard Ethernet, a USB network dongle) is never
offered to clients, so you cannot accidentally cut off the machine you are connected to.

Details: [docs/LINUX-INSTALL.md](docs/LINUX-INSTALL.md). Raspberry Pi specifics (coexisting with the original
VirtualHere server, Debian library versions): [docs/RASPBERRY-PI.md](docs/RASPBERRY-PI.md). Verified on real
Raspberry Pi 4 hardware (Debian 13, aarch64): service install, USB mass-storage share, bind/unbind, and
sysfs-based device naming.

### Run from source (any platform, no installer)

```
pip install -r requirements.txt
python -m vhserver --fake-disk --port 7580        # try it without hardware: an 8 MB RAM disk
sudo python -m vhserver                           # share the real USB devices (Linux, needs root)
python -m vhserver --windows-bind                 # Windows, from an administrator terminal
```

In the VirtualHere client the server appears by itself (Auto-Find); or add it by hand with
`vhui64 -t "MANUAL HUB ADD,<ip>:<port>"` and right-click a device -> "Use this device".

Useful options: `--name`, `--port`, `--bind`, `--allow CIDR`, `--ignore VID:PID`, `--share-hubs`, `--share-input`,
`--no-mdns`, `-v`.

## Security

Optional **device passwords**, **SSL** and **nicknames** are described in [docs/SECURITY.md](docs/SECURITY.md)
(`vhserver password`, `vhserver tls enable`). Without a password the stock protocol has no authentication, so
access is limited by **source address**: by default only loopback, private (RFC 1918), link-local and Tailscale
(100.64.0.0/10) addresses may connect; change it with `--allow CIDR` (repeatable) and `--bind ADDRESS`. Boot
keyboards and mice are never offered unless you pass `--share-input` (a remote user could otherwise read what is
typed). Use `--ignore VID:PID` for other devices that must stay local, and keep the port off the public internet.
Frames are size-limited, LZ4 expansion is capped, slow or silent clients are dropped, and transfer lengths and
timeouts are clamped.

## Building the packages yourself

```
packaging\build.ps1                                  # Windows installer (PyInstaller + Inno Setup)
bash packaging/linux/build-deb.sh                     # Linux .deb (pure Python, all architectures)
bash packaging/linux/build-tar.sh                     # generic Linux tar.gz + install.sh
```

Output lands in `dist/`.

## Development

```
python -m pytest tests --cov=vhserver
```

Layout: `wire.py` (framing, LZ4), `protocol.py` (payload layouts), `server.py` (asyncio server),
`libusb_backend.py` / `fakedisk.py` (USB backends), `discovery.py` (mDNS). Backends implement `UsbBackend` in
`backend.py`; transfers are blocking calls returning `(status, data)` with negative errno on failure.
