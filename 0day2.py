from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID, BasicConstraints, KeyUsage, DNSName, SubjectAlternativeName
from cryptography import x509
import datetime

def generate_key_pair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def generate_malicious_certificate():
    key = generate_key_pair()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
		        x509.NameAttribute(NameOID.LOCALITY_NAME, u"127.0.0.1"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"GhostSec Hackers"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"www.eyephuckbitches.wordpress.com"),
    ])
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)\
        .add_extension(
            KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                key_agreement=True,
                encipher_only=False,
                decipher_only=False,
                crl_sign=True,
            ), critical=True)\
        .add_extension(
            SubjectAlternativeName([DNSName(u"www.eyephuckbitches.wordpress.com")]), critical=False
        )\
        .sign(key, hashes.SHA256())
    return cert, key

def export_cert_key_to_pem(cert, key):
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem

# Example usage:
cert, key = generate_malicious_certificate()
cert_pem, key_pem = export_cert_key_to_pem(cert, key)

with open("malicious_cert.pem", "wb") as cert_file:
    cert_file.write(cert_pem)
with open("malicious_key.pem", "wb") as key_file:
    key_file.write(key_pem)

print("Malicious certificate and key have been generated and saved.")