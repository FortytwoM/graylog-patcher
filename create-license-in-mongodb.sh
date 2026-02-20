#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_jwt_file>"
    echo "Example: $0 output/license-jwt.txt"
    exit 1
fi

JWT_FILE="$1"

if [ ! -f "$JWT_FILE" ]; then
    echo "[ERROR] JWT file not found: $JWT_FILE"
    exit 1
fi

JWT_TOKEN=$(cat "$JWT_FILE" | tr -d '\r\n' | grep -E "^eyJ" | head -1)

if [ -z "$JWT_TOKEN" ]; then
    echo "[ERROR] JWT token not found in file: $JWT_FILE"
    exit 1
fi

echo "=== Inserting license into MongoDB ==="
echo ""

if ! docker ps | grep -q graylog-mongo; then
    echo "[ERROR] Container graylog-mongo is not running"
    echo "Start it with: docker compose up -d"
    exit 1
fi

echo "Inserting license into MongoDB..."
docker exec -i graylog-mongo mongosh graylog --quiet <<EOF
var deleted = db.licenses.deleteMany({});
print("Deleted documents: " + deleted.deletedCount);

db.licenses.find().forEach(function(d) {
  if (d.license) {
    var p = d.license.split('.');
    if (p[0]) {
      try {
        var h = JSON.parse(Buffer.from(p[0], 'base64').toString());
        if (h.alg === 'none') { db.licenses.deleteOne({_id: d._id}); print("Deleted document with alg=none"); }
      } catch(e) {}
    }
  }
});

var jwtToken = "$JWT_TOKEN";
var parts = jwtToken.split('.');
if (parts.length !== 3) { throw new Error("JWT must have 3 parts (header.payload.signature)"); }
var header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf-8'));
if (header.alg !== 'RS256') { throw new Error("JWT must be RS256, got alg=" + header.alg + ". Rebuild: docker run ... graylog-license-generator:latest"); }
print("JWT algorithm: " + header.alg + " (OK)");
var payloadB64 = parts[1];
while (payloadB64.length % 4 !== 0) {
    payloadB64 += "=";
}

var decoded = Buffer.from(payloadB64, 'base64').toString('utf-8');
var payload = JSON.parse(decoded);

var licenseId = payload.licenseId || payload.id || "generated-license-001";
var subject = payload.subject || payload.sub || "graylog-enterprise";
var issuedAt = payload.issuedAt || payload.issued_at || payload.iat || Math.floor(Date.now() / 1000);
var expirationDate = payload.expirationDate || payload.expiration_date || payload.exp || (issuedAt + 365*24*60*60);

function toMs(v) {
  if (typeof v === 'string') return new Date(v).getTime();
  var n = Number(v);
  return (n > 1e12 || n < 0) ? n : n * 1000;
}
issuedAt = toMs(issuedAt);
expirationDate = toMs(expirationDate);

// LicenseDto uses SnakeCaseStrategy -> contract_id; JwtLicenseParser fallback handles contractId for License
var docId = new ObjectId();
var contractIdVal = payload.contract_id || new ObjectId().toString();
if (!/^[a-f0-9]{24}$/i.test(contractIdVal)) contractIdVal = new ObjectId().toString();
var result = db.licenses.insertOne({
    _id: docId,
    id: String(licenseId),
    license: jwtToken,
    subject: String(subject),
    issued_at: new Date(issuedAt),
    expiration_date: new Date(expirationDate),
    contract_id: String(contractIdVal)
});

print("[OK] License created: " + result.insertedId);

// LicenseChecker.checkLicenseStatusDrawDown looks up the contract via contractDbService.get(id);
// missing document causes "License {} has no contract ID" log message
db.contracts.deleteMany({});
var contractOid = ObjectId(contractIdVal);
var now = new Date();
var endDate = new Date(expirationDate);
db.contracts.insertOne({
    _id: contractOid,
    token_subject: String(subject),
    activation_token: "",
    entitlements_remaining: [],
    license_ids: [String(licenseId)],
    encrypted_keystore_value: "",
    encrypted_keystore_salt: "",
    start_date: now,
    end_date: endDate,
    company_name: "Graylog Enterprise"
});
print("[OK] Contract created in 'contracts': " + contractOid);

var colls = db.getCollectionNames();
["license_traffic_state", "drawdown_state", "traffic_state", "license_drawdown_state", "remaining_traffic"].forEach(function(c) {
  if (colls.indexOf(c) !== -1) {
    var r = db[c].deleteMany({});
    if (r.deletedCount > 0) print("Cleared traffic state: " + c + ", deleted: " + r.deletedCount);
  }
});

var doc = db.licenses.findOne();
print("\nField verification:");
print("id: " + (doc.id ? "[OK] " + doc.id : "[ERROR] MISSING"));
print("subject: " + (doc.subject ? "[OK] " + doc.subject : "[ERROR] MISSING"));
print("issued_at: " + (doc.issued_at !== undefined ? "[OK] " + doc.issued_at + " (type: " + (typeof doc.issued_at) + ")" : "[ERROR] MISSING"));
print("expiration_date: " + (doc.expiration_date !== undefined ? "[OK] " + doc.expiration_date + " (type: " + (typeof doc.expiration_date) + ")" : "[ERROR] MISSING"));
print("contract_id: " + (doc.contract_id ? "[OK] " + doc.contract_id + " (24 hex)" : "[WARN] missing"));

var headerB64 = parts[0];
while (headerB64.length % 4 !== 0) {
    headerB64 += "=";
}
var header = JSON.parse(Buffer.from(headerB64, 'base64').toString('utf-8'));
print("JWT alg: " + header.alg);
EOF

echo ""
echo "[OK] Done! License created in MongoDB"
echo ""
echo "Restart Graylog: docker compose restart graylog"
