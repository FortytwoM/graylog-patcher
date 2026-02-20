# Graylog Enterprise License Patcher

Bytecode-level patcher that activates Graylog Enterprise features by modifying the `enterprise-plugin.jar` at runtime via [Javassist](https://www.javassist.org/). Generates a self-signed JWT license, replaces the JKS keystore inside the JAR, and patches several classes to bypass license validation.

**Tested on Graylog Enterprise 7.0.x.**

## How it works

The patcher runs inside a Docker container and performs the following steps:

1. **RSA key generation** — creates a 2048-bit RSA keypair and an X.509 certificate.
2. **JKS replacement** — replaces the `license-keys.jks` keystore inside the JAR with one containing the new certificate.
3. **Bytecode patching** — a single `UnifiedPatcher` (Javassist) reads the JAR once, patches all classes in one JVM process, and writes the JAR once:
   - `JwtLicenseParser` — fixes `iat`/`exp`/`nbf` Date-to-long conversion, bypasses signature verification on `SignatureException`, and injects a fallback `contractId`.
   - `LicenseChecker` — suppresses violation checks and forces `active = true` for the generated license.
   - `DefaultLicenseManager` — makes `hasValidLicense()` and `hasUnexpiredLicense()` always return `true`; adds a fallback in `getLicenseStatus()` so the UI receives a valid status for every feature subject.
   - `DrawdownLicenseService` — makes `checkout()` a no-op to prevent "Failed to decrypt keystore" errors.
   - `TrafficThresholdService` — prevents "License volume has been used" warnings.
   - Dynamic patching of any class containing `"has no contract ID"` or `"volume has been used"` strings.
4. **JWT generation** — creates an RS256-signed JWT with all required claims.
5. **MongoDB setup** — inserts the license document and a matching contract into MongoDB.

## Project structure

```
├── Dockerfile.license-generator   # Docker image for building the patched JAR
├── build-patched-jar.sh           # Main build script (runs inside Docker)
├── graylog-patcher.py             # Python orchestrator (key gen, JWT, patch-all)
├── create-license-in-mongodb.sh   # Inserts license + contract into MongoDB
├── docker-compose.yml             # Graylog + MongoDB + OpenSearch stack
├── tools/
│   └── UnifiedPatcher.java        # Single-pass bytecode patcher (all patches in one JVM)
└── input/                         # Place the original enterprise-plugin.jar here
```

## Prerequisites

- Docker & Docker Compose
- A running Graylog Enterprise instance (the `docker-compose.yml` provides one)

## Quick start

### 1. Start the stack

```bash
docker compose up -d
```

Wait for Graylog to fully start (check `http://localhost:9000`).

### 2. Extract the original JAR

```bash
mkdir -p input
docker cp graylog:/usr/share/graylog/plugins-merged/graylog-plugin-enterprise-7.0.3.jar input/enterprise-plugin.jar
```

### 3. Build the Docker image and generate the patched JAR

```bash
docker build -f Dockerfile.license-generator -t graylog-license-generator:latest .
docker run --rm -v "$(pwd)/input:/input" -v "$(pwd)/output:/output" graylog-license-generator:latest
```

This produces in `output/`:
- `enterprise-plugin-patched.jar` — the patched plugin
- `license-jwt.txt` — the JWT license token
- `license_private_key.pem`, `license_public_key.pem`, `license_certificate.pem` — keys

### 4. Deploy the patched JAR

```bash
docker cp output/enterprise-plugin-patched.jar graylog:/usr/share/graylog/plugins-merged/graylog-plugin-enterprise-7.0.3.jar
docker cp output/enterprise-plugin-patched.jar graylog:/usr/share/graylog/plugins-default/graylog-plugin-enterprise-7.0.3.jar
```

### 5. Insert the license into MongoDB

```bash
bash create-license-in-mongodb.sh output/license-jwt.txt
```

### 6. Restart Graylog

```bash
docker compose restart graylog
```

### 7. Verify

Open `http://localhost:9000` (login: `admin` / `admin`).  
All Enterprise features (Reporting, Archive, Auditlog, Customization, Security) should now show as licensed.

API check:
```bash
curl -s -u admin:admin "http://localhost:9000/api/plugins/org.graylog.plugins.license/licenses/status" | python3 -m json.tool
```

Expected: `"active": true`, `"valid": true`.

## Patched classes reference

| Class | Method | Patch |
|-------|--------|-------|
| `JwtLicenseParser` | `parse(Claims)` | Converts Date objects to epoch seconds for `iat`/`exp`/`nbf` |
| `JwtLicenseParser` | `parseToken(String)` | On `SignatureException`, decodes payload without verification |
| `JwtLicenseParser` | `parse(LicenseDto)` | Injects fallback `contractId` for drawdown licenses |
| `LicenseChecker` | `checkViolations*` | Returns early (empty/void) for license `generated-license-001` |
| `LicenseChecker` | `checkLicenseStatus(License, ZonedDateTime, boolean)` | Forces `active = true` (`$3 = true`) |
| `DefaultLicenseManager` | `hasValidLicense(URI)` | Always returns `true` |
| `DefaultLicenseManager` | `hasUnexpiredLicense(URI)` | Always returns `true` |
| `DefaultLicenseManager` | `getLicenseStatus(URI, boolean)` | Falls back to `getLicenseStatuses()` when status map is empty |
| `DefaultLicenseManager` | `getActiveLicenseStatus()` | Same fallback |
| `DefaultLicenseManager` | `findReportLicenseStatus()` | Same fallback |
| `DrawdownLicenseService` | `checkout()` | No-op (prevents keystore decryption errors) |
| `TrafficThresholdService` | `*(License)` / `*(String)` | Returns empty/false for our license/contract ID |

## Notes

- The Illuminate Content Hub shows packs from the **OPEN** bundle only. Enterprise/Security packs require downloading from the Illuminate Hub (cloud.graylog.com), which is not possible with a self-signed license.
- The generated license ID is `generated-license-001` with contract ID `a1b2c3d4e5f60789012340ab`.
- Traffic limit is set to ~1 PB (`999999999999999` bytes) in the JWT claims.

## Disclaimer

This project is for **educational and research purposes only**. Use it at your own risk. It is not affiliated with or endorsed by Graylog, Inc.
