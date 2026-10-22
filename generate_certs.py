"""
TLS Certificate Generator utility.
Generates self-signed certificate and private key for encrypted TLS file transfers.
"""

from datetime import datetime, timezone, timedelta
import ipaddress
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import config


def generate_self_signed_cert(
    cert_path: Path = config.DATA_DIR / "server.crt",
    key_path: Path = config.DATA_DIR / "server.key",
    host: str = "127.0.0.1"
) -> Tuple[Path, Path]:
    """Generate self-signed certificate and private key."""
    cert_path = Path(cert_path)
    key_path = Path(key_path)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Subject & Issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Transfer"),
    ])

    alt_names = [x509.DNSName("localhost")]
    try:
        ip_obj = ipaddress.ip_address(host)
        alt_names.append(x509.IPAddress(ip_obj))
    except ValueError:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    # Write private key
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated TLS Certificate: {cert_path}")
    print(f"Generated TLS Private Key: {key_path}")
    return cert_path, key_path


if __name__ == "__main__":
    generate_self_signed_cert()
