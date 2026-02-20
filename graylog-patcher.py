#!/usr/bin/env python3
"""
Graylog Enterprise JAR patcher:
  - RSA key generation
  - X.509 certificate creation
  - JKS replacement inside JAR
  - JWT license generation
"""

import sys
import os
import zipfile
import time
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key(key, path, is_private=True):
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    with open(path, 'wb') as f:
        f.write(pem)
    print(f"[OK] Key saved: {path}")

def load_private_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

def create_certificate(private_key, public_key, cert_path):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Graylog"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Enterprise"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Graylog"),
        x509.NameAttribute(NameOID.COMMON_NAME, "graylog-license-key"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365*10)
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())

    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[OK] Certificate created: {cert_path}")
    return cert_path

def replace_file_in_jar(original_jar_path, file_to_replace_path, new_jar_path, internal_path_in_jar):
    print(f"Replacing JKS in JAR: {internal_path_in_jar}")

    if not os.path.exists(original_jar_path):
        print(f"[ERROR] Original JAR not found: {original_jar_path}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(file_to_replace_path):
        print(f"[ERROR] Replacement file not found: {file_to_replace_path}", file=sys.stderr)
        sys.exit(1)

    with open(file_to_replace_path, 'rb') as f:
        new_file_data = f.read()

    processed_files = set()
    with zipfile.ZipFile(original_jar_path, 'r') as zin:
        with zipfile.ZipFile(new_jar_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == internal_path_in_jar:
                    continue
                if item.filename not in processed_files:
                    zout.writestr(item, zin.read(item.filename))
                    processed_files.add(item.filename)
            zout.writestr(internal_path_in_jar, new_file_data)

    print(f"[OK] JKS replaced in JAR: {new_jar_path}")


def run_unified_patcher(jar_path, output_jar_path, app_dir=None):
    """Compile and run UnifiedPatcher — single JVM process, single JAR pass."""
    import subprocess
    import tempfile

    app_dir = app_dir or os.path.dirname(os.path.abspath(__file__))
    tools_dir = os.path.join(app_dir, "tools")
    javassist_jar = os.path.join(tools_dir, "javassist.jar")
    patcher_src = os.path.join(tools_dir, "UnifiedPatcher.java")
    jar_abs = os.path.abspath(jar_path)
    out_abs = os.path.abspath(output_jar_path)

    if not os.path.exists(jar_path):
        print(f"[ERROR] JAR not found: {jar_path}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(javassist_jar):
        javassist_url = "https://repo1.maven.org/maven2/org/javassist/javassist/3.29.2-GA/javassist-3.29.2-GA.jar"
        try:
            import urllib.request
            print(f"Downloading Javassist to {javassist_jar}...")
            urllib.request.urlretrieve(javassist_url, javassist_jar)
            if not os.path.exists(javassist_jar):
                raise RuntimeError("download failed")
        except Exception as ex:
            print(f"[ERROR] Javassist not found: {javassist_jar}", file=sys.stderr)
            print(f"Download manually: {javassist_url}", file=sys.stderr)
            sys.exit(1)
    if not os.path.exists(patcher_src):
        print(f"[ERROR] UnifiedPatcher not found: {patcher_src}", file=sys.stderr)
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="unified_patch_") as tmp:
        build_dir = os.path.join(tmp, "build")
        os.makedirs(build_dir, exist_ok=True)
        proc = subprocess.run(
            ["javac", "-cp", javassist_jar, "-d", build_dir, patcher_src],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print("[ERROR] UnifiedPatcher compilation failed:", file=sys.stderr)
            print(proc.stderr or proc.stdout, file=sys.stderr)
            sys.exit(1)
        cp_sep = ";" if sys.platform.startswith("win") else ":"
        run_cp = cp_sep.join([build_dir, javassist_jar, jar_abs])
        proc = subprocess.run(
            ["java", "-cp", run_cp, "UnifiedPatcher", jar_abs, out_abs],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print("[ERROR] UnifiedPatcher failed:", file=sys.stderr)
            print(proc.stderr or proc.stdout, file=sys.stderr)
            sys.exit(1)
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)
    print(f"[OK] All bytecode patches applied: {output_jar_path}")


def create_jwt_rsa(claims, private_key):
    return jwt.encode(claims, private_key, algorithm='RS256')

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 graylog-patcher.py generate-keys [work_dir]")
        print("  python3 graylog-patcher.py create-cert <private_key> <cert_path>")
        print("  python3 graylog-patcher.py replace-jks <jar> <jks> <output_jar>")
        print("  python3 graylog-patcher.py patch-all <jar> <output_jar> [app_dir]")
        print("  python3 graylog-patcher.py create-jwt <private_key>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "generate-keys":
        work_dir = sys.argv[2] if len(sys.argv) > 2 else "."
        os.chdir(work_dir)
        print("Generating RSA keypair...")
        private_key, public_key = generate_rsa_keypair()
        save_key(private_key, 'license_private_key.pem', is_private=True)
        save_key(public_key, 'license_public_key.pem', is_private=False)
        create_certificate(private_key, public_key, 'license_certificate.pem')

    elif command == "create-cert":
        if len(sys.argv) < 4:
            print("[ERROR] Provide: <private_key> <cert_path>", file=sys.stderr)
            sys.exit(1)
        private_key = load_private_key(sys.argv[2])
        create_certificate(private_key, private_key.public_key(), sys.argv[3])

    elif command == "replace-jks":
        if len(sys.argv) < 5:
            print("[ERROR] Provide: <jar> <jks> <output_jar>", file=sys.stderr)
            sys.exit(1)
        replace_file_in_jar(sys.argv[2], sys.argv[3], sys.argv[4],
                            "org/graylog/plugins/license/license-keys.jks")

    elif command == "patch-all":
        if len(sys.argv) < 4:
            print("[ERROR] Provide: <jar> <output_jar> [app_dir]", file=sys.stderr)
            sys.exit(1)
        app_dir = sys.argv[4] if len(sys.argv) > 4 else None
        run_unified_patcher(sys.argv[2], sys.argv[3], app_dir)

    elif command == "create-jwt":
        if len(sys.argv) < 3:
            print("[ERROR] Provide: <private_key>", file=sys.stderr)
            sys.exit(1)
        private_key = load_private_key(sys.argv[2])

        now_sec = int(time.time())
        expiration_sec = now_sec + (36500 * 24 * 60 * 60)
        now_iso = datetime.utcfromtimestamp(now_sec).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        exp_iso = datetime.utcfromtimestamp(expiration_sec).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        license_id_val = "generated-license-001"
        contract_id_val = "a1b2c3d4e5f60789012340ab"
        claims = {
            "iss": "Graylog, Inc.",
            "sub": "graylog-enterprise",
            "iat": now_sec,
            "issuedAt": now_sec,
            "exp": expiration_sec,
            "nbf": now_sec,
            "jti": license_id_val,
            "issued_at": now_iso,
            "expiration_date": exp_iso,
            "aud": "graylog-enterprise",
            "id": license_id_val,
            "licenseId": license_id_val,
            "subject": "graylog-enterprise",
            "contract_id": contract_id_val,
            "version": 3,
            "trial": False,
            "recipient": {
                "company": "Graylog",
                "name": "graylog-enterprise",
                "email": "enterprise@graylog.org",
            },
            "licensee": {
                "company": "Graylog",
                "name": "graylog-enterprise",
                "email": "enterprise@graylog.org",
            },
            "enterprise": {
                "cluster_ids": [],
                "traffic_check_range": 86400000,
                "allowed_remote_check_failures": 3,
                "allowed_traffic_violations": 0,
                "traffic_limit": 999999999999999,
                "expiration_warning_range": 2592000000,
                "require_remote_check": False,
            },
            "entitlements": [],
        }
        print(create_jwt_rsa(claims, private_key), end='')

    else:
        print(f"[ERROR] Unknown command: {command}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
