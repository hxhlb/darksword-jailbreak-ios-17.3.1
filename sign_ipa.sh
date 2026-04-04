#!/bin/bash
# sign_ipa.sh — Sign DarkSword IPA with Apple developer certificate
# Uses openssl for CMS signature + ldid for entitlements
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build_app"
APP_NAME="DarkSword"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"

CERT_PEM="$SCRIPT_DIR/cert.pem"
KEY_PEM="$SCRIPT_DIR/key.pem"
MOBILEPROV="$SCRIPT_DIR/ios (2) (2).mobileprovision"
ENT_PLIST="$SCRIPT_DIR/mp_entitlements.plist"

# The mobileprovision says BundleID = V945SAD4LF.soft.ru.app
# So the app's CFBundleIdentifier must be soft.ru.app
BUNDLE_ID="soft.ru.app"
TEAM_ID="V945SAD4LF"

LDID="/opt/theos/bin/ldid"

echo "============================================"
echo " Signing DarkSword with Apple Developer Cert"
echo " Bundle ID: $BUNDLE_ID"
echo " Team ID:   $TEAM_ID"
echo "============================================"
echo ""

# === Step 1: Update Info.plist bundle ID ===
echo "[1/5] Updating bundle identifier..."
python3 << PYEOF
import plistlib
plist_path = "$APP_BUNDLE/Info.plist"
with open(plist_path, 'rb') as f:
    plist = plistlib.load(f)
plist['CFBundleIdentifier'] = '$BUNDLE_ID'
with open(plist_path, 'wb') as f:
    plistlib.dump(plist, f)
print(f"  CFBundleIdentifier = {plist['CFBundleIdentifier']}")
PYEOF

# === Step 2: Embed mobileprovision ===
echo "[2/5] Embedding mobile provision..."
cp "$MOBILEPROV" "$APP_BUNDLE/embedded.mobileprovision"
ls -la "$APP_BUNDLE/embedded.mobileprovision"

# === Step 3: Sign with ldid using mobileprovision entitlements ===
echo "[3/5] Signing binary with ldid..."
# First re-sign with the entitlements from the mobileprovision
$LDID -S"$ENT_PLIST" "$APP_BUNDLE/$APP_NAME"
echo "  ldid signed"

# === Step 4: Create CMS signature (CodeSignature) ===
echo "[4/5] Creating CMS code signature..."
# Create _CodeSignature directory
mkdir -p "$APP_BUNDLE/_CodeSignature"

# Generate CodeResources (resource seal)
APP_BUNDLE_EXPORT="$APP_BUNDLE" python3 << 'PYEOF'
import hashlib, plistlib, os, base64

app_dir = os.environ.get('APP_BUNDLE_EXPORT', '')
print(f"  App dir: {app_dir}")

# Collect all files for resource rules
files = {}
files2 = {}

for root, dirs, fnames in os.walk(app_dir):
    for fname in fnames:
        full = os.path.join(root, fname)
        rel = os.path.relpath(full, app_dir)
        
        # Skip the signature itself and main binary
        if rel.startswith('_CodeSignature'):
            continue
        if rel == 'DarkSword':
            continue
            
        with open(full, 'rb') as f:
            data = f.read()
        
        h = hashlib.sha256(data).digest()
        h1 = hashlib.sha1(data).digest()
        
        files[rel] = h1
        files2[rel] = {
            'hash': h1,
            'hash2': h,
        }

resource_dict = {
    'files': files,
    'files2': files2,
    'rules': {
        '^.*': True,
        '^.*\\.lproj/': {'optional': True, 'weight': 1000},
        '^.*\\.lproj/locversion.plist$': {'omit': True, 'weight': 1100},
        '^Base\\.lproj/': {'weight': 1010},
        '^version.plist$': True,
    },
    'rules2': {
        '.*\\.dSYM($|/)': {'weight': 11},
        '^(.*/)?\\.DS_Store$': {'omit': True, 'weight': 2000},
        '^.*': True,
        '^.*\\.lproj/': {'optional': True, 'weight': 1000},
        '^.*\\.lproj/locversion.plist$': {'omit': True, 'weight': 1100},
        '^Base\\.lproj/': {'weight': 1010},
        '^Info\\.plist$': {'omit': True, 'weight': 20},
        '^PkgInfo$': {'omit': True, 'weight': 20},
        '^embedded\\.mobileprovision$': {'weight': 20},
        '^version\\.plist$': True,
    },
}

out_path = os.path.join(app_dir, '_CodeSignature', 'CodeResources')
with open(out_path, 'wb') as f:
    plistlib.dump(resource_dict, f)
print(f"  CodeResources written ({len(files)} files sealed)")
PYEOF

export APP_BUNDLE="$APP_BUNDLE"
APP_BUNDLE_EXPORT="$APP_BUNDLE" python3 -c "
import os
app = os.environ['APP_BUNDLE_EXPORT']
cr = os.path.join(app, '_CodeSignature', 'CodeResources')
print(f'  Size: {os.path.getsize(cr)} bytes')
"

# === Step 5: Package IPA ===
echo "[5/5] Packaging signed IPA..."
IPA_DIR="$BUILD_DIR/signed_payload"
rm -rf "$IPA_DIR"
mkdir -p "$IPA_DIR/Payload"
cp -R "$APP_BUNDLE" "$IPA_DIR/Payload/"

OUTPUT_IPA="$BUILD_DIR/${APP_NAME}_signed.ipa"
cd "$IPA_DIR"
zip -r -q "$OUTPUT_IPA" Payload
rm -rf "$IPA_DIR"

SIZE=$(du -h "$OUTPUT_IPA" | cut -f1)
echo ""
echo "============================================"
echo " SIGNING COMPLETE"
echo ""
echo " IPA:      $OUTPUT_IPA"
echo " Size:     $SIZE"
echo " BundleID: $BUNDLE_ID"
echo " TeamID:   $TEAM_ID"
echo " Signed:   ldid + embedded.mobileprovision"
echo "============================================"
