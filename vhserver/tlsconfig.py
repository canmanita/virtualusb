"""TLS for the SSL port: a private CA plus a server certificate (the stock client wants a CA file, not a host name).

``generate_certificates`` creates ``ca.pem``/``ca.key`` and ``server.pem``/``server.key``. Give ``ca.pem`` to every
client (Advanced Settings -> Certificate Authority File); keep ``ca.key`` on the server only.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import re
import ssl
from dataclasses import dataclass
from pathlib import Path

CA_DAYS = 3650
LEAF_DAYS = 1825
KEY_BITS = 2048  # accepted by every TLS stack the clients ship
MAX_CN = 64      # X.509 limit for a common name
_CLIENT_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class TlsError(Exception):
    pass


def _crypto():
    """The ``cryptography`` package, needed only to create or inspect certificates (serving TLS uses the stdlib)."""
    try:
        import cryptography  # noqa: F401
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as exc:
        raise TlsError("the 'cryptography' package is needed to create certificates "
                       "(Linux: sudo apt install python3-cryptography)") from exc
    return x509, hashes, serialization, rsa, ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class TlsFiles:
    ca_cert: Path
    ca_key: Path
    server_cert: Path
    server_key: Path


@dataclass(frozen=True)
class CertificateInfo:
    subject: str
    names: tuple[str, ...]
    days_left: int
    is_ca: bool


def _new_key():
    rsa = _crypto()[3]
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)


def _name(common_name: str):
    x509, *_rest, NameOID = _crypto()
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VHServer"),
                      x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    path.unlink(missing_ok=True)  # O_CREAT keeps the mode of a file that already exists, so start from nothing
    fd = os.open(path, flags, 0o600)  # owner only where the platform has file modes; elsewhere the folder ACL applies
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _pem_key(key) -> bytes:
    serialization = _crypto()[2]
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _builder(subject, issuer, public_key, days: int):
    x509 = _crypto()[0]
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days)))


def _load_ca(files: TlsFiles):
    x509, _hashes, serialization, *_rest = _crypto()
    try:
        ca_cert = x509.load_pem_x509_certificate(files.ca_cert.read_bytes())
        ca_key = serialization.load_pem_private_key(files.ca_key.read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise TlsError(f"cannot read the CA in {files.ca_cert.parent}: {exc}") from exc
    return ca_cert, ca_key


def generate_certificates(directory: Path, *, common_name: str, hostnames: list[str], addresses: list[str],
                          force: bool = False) -> TlsFiles:
    files = TlsFiles(directory / "ca.pem", directory / "ca.key", directory / "server.pem", directory / "server.key")
    present = [p.is_file() for p in (files.ca_cert, files.ca_key, files.server_cert, files.server_key)]
    if not force and all(present):
        return files
    if not force and any(present):
        raise TlsError(f"{directory} holds only part of the certificates; regenerating would replace the CA that "
                       "the clients trust: restore the missing file or use --force")
    try:
        return _generate(files, directory, common_name, hostnames, addresses)
    except ValueError as exc:  # invalid host name or address
        raise TlsError(f"cannot create the certificates: {exc}") from exc


def _generate(files: TlsFiles, directory: Path, common_name: str, hostnames: list[str], addresses: list[str]) -> TlsFiles:
    x509, hashes, serialization, _rsa, ExtendedKeyUsageOID, _NameOID = _crypto()
    directory.mkdir(parents=True, exist_ok=True)

    ca_key = _new_key()
    common_name = common_name[:MAX_CN - 3]
    ca_name = _name(f"{common_name} CA")
    ca_cert = (_builder(ca_name, ca_name, ca_key.public_key(), CA_DAYS)
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                            key_encipherment=False, data_encipherment=False, key_agreement=False,
                                            encipher_only=False, decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))

    server_key = _new_key()
    alt_names: list[x509.GeneralName] = [x509.DNSName(h) for h in hostnames]
    for address in addresses:
        alt_names.append(x509.IPAddress(ipaddress.ip_address(address)))
    builder = (_builder(_name(common_name), ca_name, server_key.public_key(), LEAF_DAYS)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    if alt_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
    server_cert = builder.sign(ca_key, hashes.SHA256())

    files.ca_cert.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_private(files.ca_key, _pem_key(ca_key))
    files.server_cert.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    _write_private(files.server_key, _pem_key(server_key))
    return files


def generate_client_certificate(files: TlsFiles, directory: Path, *, common_name: str) -> tuple[Path, Path]:
    """A client certificate signed by the CA, for servers that require them (``ssl_use_client_certs``)."""
    if not _CLIENT_NAME.match(common_name):
        raise TlsError("the client name may only contain letters, digits, '.', '_' and '-'")
    x509, hashes, serialization, _rsa, ExtendedKeyUsageOID, _NameOID = _crypto()
    ca_cert, ca_key = _load_ca(files)
    key = _new_key()
    cert = (_builder(_name(common_name), ca_cert.subject, key.public_key(), LEAF_DAYS)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / f"{common_name}.pem", directory / f"{common_name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private(key_path, _pem_key(key))
    return cert_path, key_path


def certificate_info(path: Path) -> CertificateInfo | None:
    try:
        x509 = _crypto()[0]
    except TlsError:
        return None
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError):
        return None
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = tuple(list(san.get_values_for_type(x509.DNSName)) +
                      [str(a) for a in san.get_values_for_type(x509.IPAddress)])
    except x509.ExtensionNotFound:
        names = ()
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    expires = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    remaining = expires - datetime.datetime.now(datetime.timezone.utc)
    return CertificateInfo(cert.subject.rfc4514_string(), names, int(remaining.total_seconds() // 86400), is_ca)


def build_context(cert: Path, key: Path, *, ca: Path | None = None, require_client_cert: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.load_cert_chain(str(cert), str(key))
        if require_client_cert:
            if ca is None:
                raise TlsError("client certificates are required but no CA file (ssl_ca) was given")
            ctx.load_verify_locations(str(ca))
            ctx.verify_mode = ssl.CERT_REQUIRED
    except (OSError, ssl.SSLError) as exc:
        raise TlsError(f"cannot use the TLS certificate {cert}: {exc}") from exc
    return ctx
