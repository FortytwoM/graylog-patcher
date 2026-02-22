#!/bin/bash
set -e

echo "=== Graylog Enterprise patched JAR generator ==="
echo ""

WORK_DIR="/tmp/work"
OUTPUT_DIR="/output"
INPUT_JAR="${1:-/input/enterprise-plugin.jar}"

mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

if [ ! -f "$INPUT_JAR" ]; then
    echo "[ERROR] JAR file not found: $INPUT_JAR"
    echo ""
    echo "Usage:"
    echo "  docker run --rm \\"
    echo "    -v \"\$(pwd)/input:/input\" \\"
    echo "    -v \"\$(pwd)/output:/output\" \\"
    echo "    graylog-license-generator:latest [path_to_jar]"
    echo ""
    echo "Example:"
    echo "  1. Copy the JAR into the input/ folder:"
    echo "     mkdir -p input"
    echo "     docker cp graylog:/usr/share/graylog/plugins-merged/graylog-plugin-enterprise-<VERSION>.jar input/enterprise-plugin.jar"
    echo ""
    echo "  2. Run the generator:"
    echo "     docker run --rm -v \"\$(pwd)/input:/input\" -v \"\$(pwd)/output:/output\" graylog-license-generator:latest"
    exit 1
fi

echo "[1/6] Copying JAR file..."
cp "$INPUT_JAR" "$WORK_DIR/enterprise-plugin-main.jar"

if [ ! -f "$WORK_DIR/enterprise-plugin-main.jar" ]; then
    echo "[ERROR] Failed to copy JAR"
    exit 1
fi

echo "[OK] JAR copied: $(du -h enterprise-plugin-main.jar | cut -f1)"

# --- Version auto-detection ---
# Priority: GRAYLOG_VERSION env > JAR filename > JAR manifest > "VERSION"
if [ -z "$GRAYLOG_VERSION" ]; then
    JAR_BASENAME=$(basename "$INPUT_JAR")
    GRAYLOG_VERSION=$(echo "$JAR_BASENAME" | sed -n 's/.*graylog-plugin-enterprise-\(.*\)\.jar/\1/p')
fi

if [ -z "$GRAYLOG_VERSION" ]; then
    GRAYLOG_VERSION=$(python3 -c "
import zipfile, sys
try:
    with zipfile.ZipFile(sys.argv[1]) as z:
        for line in z.read('META-INF/MANIFEST.MF').decode('utf-8', errors='ignore').splitlines():
            for key in ['Implementation-Version', 'Bundle-Version', 'Graylog-Plugin-Properties-Version']:
                if line.startswith(key + ':'):
                    print(line.split(':', 1)[1].strip())
                    sys.exit(0)
except Exception:
    pass
" "$WORK_DIR/enterprise-plugin-main.jar" 2>/dev/null) || true
fi

if [ -z "$GRAYLOG_VERSION" ]; then
    GRAYLOG_VERSION="VERSION"
    echo "[WARN] Could not auto-detect Graylog version; using placeholder."
    echo "       Set GRAYLOG_VERSION env or use the original JAR filename."
else
    echo "[OK] Graylog version: $GRAYLOG_VERSION"
fi

PLUGIN_JAR_NAME="graylog-plugin-enterprise-${GRAYLOG_VERSION}.jar"
echo ""

echo "[2/6] Generating RSA keys and certificate..."
python3 /app/graylog-patcher.py generate-keys "$WORK_DIR" > /tmp/gen-keys.log 2>&1

if [ ! -f "license_public_key.pem" ] || [ ! -f "license_private_key.pem" ] || [ ! -f "license_certificate.pem" ]; then
    echo "[ERROR] Keys or certificate were not generated"
    echo "Generation log:"
    cat /tmp/gen-keys.log
    exit 1
fi

echo "[OK] Keys and certificate generated"

echo "  Verifying key pair consistency..."
python3 -c "
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

with open('license_certificate.pem', 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read(), default_backend())

with open('license_private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

if cert.public_key().public_numbers() != private_key.public_key().public_numbers():
    print('[ERROR] Public key in certificate does not match the private key!')
    exit(1)
else:
    print('[OK] Keys match')
" || {
    echo "[ERROR] Key pair verification failed"
    exit 1
}
echo ""

echo "[3/6] Extracting JKS from JAR..."
python3 -c "import zipfile; jar = zipfile.ZipFile('enterprise-plugin-main.jar', 'r'); jar.extract('org/graylog/plugins/license/license-keys.jks', 'extracted')" 2>/dev/null || {
    echo "[ERROR] Failed to extract JKS from JAR"
    echo "Make sure this is a valid Graylog Enterprise JAR file"
    exit 1
}

if [ ! -f "extracted/org/graylog/plugins/license/license-keys.jks" ]; then
    echo "[ERROR] JKS not found in JAR"
    echo "Expected path: org/graylog/plugins/license/license-keys.jks"
    exit 1
fi

echo "[OK] JKS extracted"
echo ""

echo "[4/6] Updating JKS with new certificate..."
keytool -delete -alias graylog-license-key -keystore extracted/org/graylog/plugins/license/license-keys.jks -storepass secret -noprompt 2>/dev/null || true

keytool -import -alias graylog-license-key -file license_certificate.pem -keystore extracted/org/graylog/plugins/license/license-keys.jks -storepass secret -noprompt -trustcacerts || {
    echo "[ERROR] Failed to import certificate into JKS"
    echo "Certificate details:"
    keytool -printcert -file license_certificate.pem 2>&1 || true
    exit 1
}

echo "  Verifying imported key..."
keytool -list -alias graylog-license-key -keystore extracted/org/graylog/plugins/license/license-keys.jks -storepass secret -noprompt > /dev/null 2>&1 || {
    echo "[ERROR] Key not found in JKS after import"
    exit 1
}
echo "  [OK] Key successfully imported into JKS"

echo "[OK] JKS updated"
echo ""

echo "[5/6] Creating patched JAR (JKS replacement)..."
python3 /app/graylog-patcher.py replace-jks \
    enterprise-plugin-main.jar \
    extracted/org/graylog/plugins/license/license-keys.jks \
    enterprise-plugin-patched.jar

if [ ! -f "enterprise-plugin-patched.jar" ]; then
    echo "[ERROR] Patched JAR was not created"
    exit 1
fi

echo "[OK] JAR with new JKS created"

echo "[6/6] Bytecode patching (single pass)..."
python3 /app/graylog-patcher.py patch-all \
    enterprise-plugin-patched.jar \
    enterprise-plugin-patched.jar \
    /app

if [ ! -f "enterprise-plugin-patched.jar" ]; then
    echo "[ERROR] Patching failed"
    exit 1
fi

echo "[OK] Patched JAR created: $(du -h enterprise-plugin-patched.jar | cut -f1)"
echo ""

echo "=== Generating JWT license ==="
JWT_TOKEN=$(python3 /app/graylog-patcher.py create-jwt license_private_key.pem 2>&1)

if [ -z "$JWT_TOKEN" ] || [[ ! "$JWT_TOKEN" =~ ^eyJ ]]; then
    echo "[ERROR] Failed to generate JWT"
    echo "Output: $JWT_TOKEN"
    exit 1
fi

echo "$JWT_TOKEN" > license-jwt.txt
echo "[OK] JWT license generated"
echo ""

echo "=== Copying results to /output ==="
cp enterprise-plugin-patched.jar "$OUTPUT_DIR/"
cp license_private_key.pem "$OUTPUT_DIR/"
cp license_public_key.pem "$OUTPUT_DIR/"
cp license_certificate.pem "$OUTPUT_DIR/" 2>/dev/null || true
cp license-jwt.txt "$OUTPUT_DIR/"
cp enterprise-plugin-main.jar "$OUTPUT_DIR/" 2>/dev/null || true

echo ""
echo "=== Done! ==="
echo ""
echo "Output files:"
echo "  - enterprise-plugin-patched.jar  (patched JAR for Graylog)"
echo "  - license_private_key.pem        (private key)"
echo "  - license_public_key.pem         (public key, already in JAR)"
echo "  - license_certificate.pem        (X.509 certificate)"
echo "  - license-jwt.txt                (JWT license for MongoDB)"
echo "  - enterprise-plugin-main.jar     (original JAR, backup)"
echo ""
echo "Next steps:"
echo "  1. Copy enterprise-plugin-patched.jar into the Graylog container:"
echo "     docker cp output/enterprise-plugin-patched.jar graylog:/usr/share/graylog/plugins-merged/${PLUGIN_JAR_NAME}"
echo "     docker cp output/enterprise-plugin-patched.jar graylog:/usr/share/graylog/plugins-default/${PLUGIN_JAR_NAME}"
echo ""
echo "  2. Insert the license into MongoDB using license-jwt.txt:"
echo "     bash create-license-in-mongodb.sh output/license-jwt.txt"
echo ""
echo "  3. Restart Graylog: docker compose restart graylog"
