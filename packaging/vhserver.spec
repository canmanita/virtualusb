# PyInstaller spec: one folder build of the server, asking for administrator rights (drivers are switched).
from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], []
for package in ("zeroconf", "ifaddr", "usb1", "cryptography"):  # compiled modules and the bundled libusb-1.0.dll
    pkg_datas, pkg_binaries, pkg_hidden = collect_all(package)
    datas += pkg_datas
    binaries += pkg_binaries
    hiddenimports += pkg_hidden

analysis = Analysis(["entry.py"], pathex=[".."], binaries=binaries, datas=datas, hiddenimports=hiddenimports,
                    excludes=["tkinter", "pytest", "unittest"], noarchive=False)
pyz = PYZ(analysis.pure)
exe = EXE(pyz, analysis.scripts, [], exclude_binaries=True, name="vhserver", console=True, uac_admin=True,
          version="version_info.txt")
coll = COLLECT(exe, analysis.binaries, analysis.datas, name="vhserver")
