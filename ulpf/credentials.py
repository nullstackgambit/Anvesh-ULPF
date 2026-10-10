"""Install-time secrets and certificates (never committed; never fetched).

`ulpf secrets init`  runtime/secrets/ (0700; files 0600):
    pii.key                            HMAC key for spec `pii:` pseudonymisation
    opensearch-<user>.user/.password   admin, ulpf-writer (Vector), ulpf-reader (UI)
`ulpf certs init`    deploy/certs/ (keys 0600), a private CA for this deployment:
    ulpf-ca.crt/.key                   CA (keep the key offline after issuing)
    ulpf-server.crt/.key               TLS syslog listener (Vector), SAN localhost/127.0.0.1
    opensearch-node.crt/.key           OpenSearch HTTP + transport (PKCS#8 key)
    opensearch-admin.crt/.key          OpenSearch security admin client certificate
    ulpf-client.crt/.key               a sender client certificate (mTLS tests)

Everything is generated locally with `cryptography` (RSA 3072, SHA-256); an
air-gapped install needs no network for any of it.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import secrets as _secrets
from pathlib import Path

from . import paths

USERS = ("admin", "ulpf-writer", "ulpf-reader")


def _write_secret(p: Path, data: bytes | str, *, force: bool) -> bool:
    if p.exists() and not force:
        return False
    p.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(p.parent, 0o700)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data.encode() if isinstance(data, str) else data)
    os.chmod(p, 0o600)
    return True


def init_secrets(*, force: bool = False) -> dict:
    out = {}
    out["pii.key"] = _write_secret(paths.SECRETS / "pii.key", _secrets.token_hex(32) + "\n", force=force)
    for u in USERS:
        out[f"opensearch-{u}"] = _write_secret(paths.SECRETS / f"opensearch-{u}.user", u + "\n", force=force)
        _write_secret(paths.SECRETS / f"opensearch-{u}.password", _secrets.token_urlsafe(24) + "\n", force=force)
    return {"dir": str(paths.SECRETS), "written": {k: ("created" if v else "kept") for k, v in out.items()}}


def password(user: str) -> str:
    return (paths.SECRETS / f"opensearch-{user}.password").read_text().strip()


# ------------------------------------------------------------ certificates
def _key():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _name(cn: str):
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ULPF"),
                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "ULPF deployment"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _pem_key(k) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _pem_cert(c) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return c.public_bytes(serialization.Encoding.PEM)


def _issue(ca_key, ca_cert, cn: str, *, server: bool, client: bool, days: int, sans: list | None = None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID

    k = _key()
    now = dt.datetime.now(dt.timezone.utc)
    eku = ([ExtendedKeyUsageOID.SERVER_AUTH] if server else []) + ([ExtendedKeyUsageOID.CLIENT_AUTH] if client else [])
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_cert.subject).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
         .not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return k, b.sign(ca_key, hashes.SHA256())


def init_certs(*, force: bool = False, days: int = 825) -> dict:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    d = paths.CERTS
    d.mkdir(parents=True, exist_ok=True)
    if (d / "ulpf-ca.crt").exists() and not force:
        return {"dir": str(d), "created": False, "note": "CA exists (use --force to re-issue everything)"}
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = _key()
    ca = (x509.CertificateBuilder().subject_name(_name("ULPF Local CA")).issuer_name(_name("ULPF Local CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days * 2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    local = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address("::1"))]
    issued = {
        "ulpf-server": _issue(ca_key, ca, "ulpf-syslog", server=True, client=False, days=days, sans=local),
        "opensearch-node": _issue(ca_key, ca, "ulpf-opensearch-node", server=True, client=True, days=days, sans=local),
        "opensearch-admin": _issue(ca_key, ca, "ulpf-admin", server=False, client=True, days=days),
        "ulpf-client": _issue(ca_key, ca, "ulpf-sender", server=False, client=True, days=days),
    }
    _write_secret(d / "ulpf-ca.key", _pem_key(ca_key), force=True)
    (d / "ulpf-ca.crt").write_bytes(_pem_cert(ca))
    for name, (k, c) in issued.items():
        _write_secret(d / f"{name}.key", _pem_key(k), force=True)
        (d / f"{name}.crt").write_bytes(_pem_cert(c))
    return {"dir": str(d), "created": True,
            "subjects": {n: c.subject.rfc4514_string() for n, (_, c) in issued.items()},
            "ca_sha256": ca.fingerprint(hashes.SHA256()).hex(),
            "not_after": (now + dt.timedelta(days=days)).isoformat(timespec="seconds"),
            "note": "move deploy/certs/ulpf-ca.key offline once certificates are issued"}
