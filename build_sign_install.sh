#!/bin/bash
# build_sign_install.sh — Build, sign, and package DarkSword in one step
set -e

export THEOS=/opt/theos
export PATH=/opt/theos/bin:$PATH

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build_app"
APP_NAME="DarkSword"
ARCH="arm64"
MIN_IOS="17.0"

CC="/opt/theos/toolchain/linux/iphone/bin/clang"
SDK="/opt/theos/sdks/iPhoneOS16.5.sdk"

BUNDLE_ID="soft.ru.app"

echo "=== PHASE 1: Compile ==="

CFLAGS="-arch $ARCH \
  -miphoneos-version-min=$MIN_IOS \
  -isysroot $SDK \
  -I$SCRIPT_DIR/darksword \
  -fobjc-arc \
  -fno-modules \
  -O2 \
  -DNDEBUG \
  -Wno-unused-function \
  -Wno-deprecated-declarations \
  -target arm64-apple-ios${MIN_IOS}"

LDFLAGS="-arch $ARCH \
  -isysroot $SDK \
  -target arm64-apple-ios${MIN_IOS} \
  -framework Foundation \
  -framework UIKit \
  -framework IOKit \
  -framework IOSurface \
  -framework CoreGraphics \
  -e _main"

SRCS=(
  app/main.m
  darksword/darksword_core.m
  darksword/darksword_exploit.m
  darksword/utils.m
  darksword/kfs.m
  darksword/postexploit.m
  darksword/trustcache.m
  darksword/bootstrap.m
  darksword/filelog.m
)

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

OBJS=()
cd "$SCRIPT_DIR"
for src in "${SRCS[@]}"; do
    base=$(basename "$src" .m)
    obj="$BUILD_DIR/${base}.o"
    echo "[CC] $src"
    $CC $CFLAGS -c "$src" -o "$obj"
    OBJS+=("$obj")
done

echo "[LD] Linking..."
$CC $LDFLAGS -o "$BUILD_DIR/$APP_NAME" "${OBJS[@]}"
file "$BUILD_DIR/$APP_NAME"

# Create .app bundle
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
mkdir -p "$APP_BUNDLE"
cp "$BUILD_DIR/$APP_NAME" "$APP_BUNDLE/$APP_NAME"

# Update Info.plist with correct bundle ID
python3 << PYEOF
import plistlib
with open("$SCRIPT_DIR/app/Info.plist", 'rb') as f:
    plist = plistlib.load(f)
plist['CFBundleIdentifier'] = '$BUNDLE_ID'
with open("$APP_BUNDLE/Info.plist", 'wb') as f:
    plistlib.dump(plist, f)
print(f"  BundleID: {plist['CFBundleIdentifier']}")
PYEOF

# LaunchScreen
mkdir -p "$APP_BUNDLE/Base.lproj/LaunchScreen.storyboardc"
cp "$SCRIPT_DIR/app/LaunchScreen.storyboard" \
   "$APP_BUNDLE/Base.lproj/LaunchScreen.storyboardc/LaunchScreen.storyboard"

echo ""
echo "=== PHASE 2: Sign ==="

MP="$SCRIPT_DIR/ios (2) (2).mobileprovision"
P12="$SCRIPT_DIR/Сертификатыnew2 (3).p12"
P12_PASS="1984"
TEAM_ID="V945SAD4LF"

# 2a. Embed mobileprovision
cp "$MP" "$APP_BUNDLE/embedded.mobileprovision"
echo "  Embedded mobileprovision"

# 2b. Extract entitlements from mobileprovision + merge with exploit entitlements
python3 << PYEOF
import plistlib

# Base from provisioning profile
mp_data = open("$MP", 'rb').read()
s = mp_data.find(b'<?xml'); e = mp_data.find(b'</plist>') + 8
ents = plistlib.loads(mp_data[s:e]).get('Entitlements', {})
ents['application-identifier'] = '${TEAM_ID}.${BUNDLE_ID}'
ents['com.apple.developer.team-identifier'] = '${TEAM_ID}'

# Merge exploit-specific entitlements from app/entitlements.plist
# Keep an explicit allowlist to avoid pulling unrelated/private keys by accident.
import os
app_ent_path = os.path.join('$SCRIPT_DIR', 'app', 'entitlements.plist')
if os.path.exists(app_ent_path):
    with open(app_ent_path, 'rb') as f:
        app_ents = plistlib.load(f)
    # These capabilities are used by exploit/runtime paths in this project:
    for key in [
        'platform-application',
        'com.apple.private.security.no-container',
        'com.apple.developer.kernel.extended-virtual-addressing',
        'com.apple.developer.kernel.increased-memory-limit',
        'com.apple.security.iokit-user-client-class',
    ]:
        if key in app_ents and key not in ents:
            ents[key] = app_ents[key]
    print(f"  Merged exploit entitlements from app/entitlements.plist")

with open('$BUILD_DIR/entitlements.plist', 'wb') as f:
    plistlib.dump(ents, f)
print(f"  Entitlements: {len(ents)} keys written")
PYEOF

# 2c. Create _CodeSignature/CodeResources using our Python tool
# (seal all non-binary resources)
python3 << PYEOF
import hashlib, os, plistlib

app_dir = '$APP_BUNDLE'
exe = 'DarkSword'

def sha1(d):   return hashlib.sha1(d).digest()
def sha256(d): return hashlib.sha256(d).digest()

files1 = {}; files2 = {}
for root, dirs, fnames in os.walk(app_dir):
    dirs[:] = [d for d in dirs if d != '_CodeSignature']
    for fname in fnames:
        fp  = os.path.join(root, fname)
        rel = os.path.relpath(fp, app_dir)
        if rel == exe: continue
        d = open(fp, 'rb').read()
        files1[rel] = sha1(d)
        files2[rel] = {'hash': sha1(d), 'hash2': sha256(d)}

cr = {
    'files':  files1,
    'files2': files2,
    'rules': {
        '^.*': True,
        '^Info\\.plist$': {'omit': True, 'weight': 20},
        '^embedded\\.mobileprovision$': {'weight': 20},
    },
    'rules2': {
        '^.*': True,
        '^Info\\.plist$': {'omit': True, 'weight': 20},
        '^PkgInfo$': {'omit': True, 'weight': 20},
        '^embedded\\.mobileprovision$': {'weight': 20},
    },
}
os.makedirs(os.path.join(app_dir, '_CodeSignature'), exist_ok=True)
with open(os.path.join(app_dir, '_CodeSignature', 'CodeResources'), 'wb') as f:
    plistlib.dump(cr, f)
print(f"  CodeResources: {len(files1)} files sealed")
PYEOF

# 2d. Sign binary with ldid + real p12 certificate
echo "  Signing with ldid + p12..."
/opt/theos/bin/ldid \
  -S"$BUILD_DIR/entitlements.plist" \
  -K"$P12" \
  -U"$P12_PASS" \
  "$APP_BUNDLE/$APP_NAME"
echo "  ldid: done"

# Verify
/opt/theos/bin/ldid -h "$APP_BUNDLE/$APP_NAME" | grep "Authority\|Team\|CandidateCDHash"


echo ""
echo "=== PHASE 3: Package IPA ==="

IPA_DIR="$BUILD_DIR/payload_tmp"
rm -rf "$IPA_DIR"
mkdir -p "$IPA_DIR/Payload"
cp -R "$APP_BUNDLE" "$IPA_DIR/Payload/"

OUTPUT_IPA="$BUILD_DIR/${APP_NAME}.ipa"
cd "$IPA_DIR"
zip -r -q "$OUTPUT_IPA" Payload
rm -rf "$IPA_DIR"

SIZE=$(du -h "$OUTPUT_IPA" | cut -f1)
echo ""
echo "============================================"
echo " BUILD + SIGN COMPLETE"
echo " IPA:      $OUTPUT_IPA"
echo " Size:     $SIZE"
echo " BundleID: $BUNDLE_ID"
echo "============================================"

# === PHASE 3b: Re-sign with zsign for proper codesignature ===
echo ""
echo "=== PHASE 3b: Re-sign with zsign ==="
ZSIGN='/mnt/c/Users/smolk/Documents/palera1n-windows/zsign_build/bin/zsign'
SIGNED_IPA="$BUILD_DIR/${APP_NAME}_signed.ipa"
if [ -x "$ZSIGN" ]; then
    "$ZSIGN" -k "$P12" -p "$P12_PASS" -m "$MP" -b "$BUNDLE_ID" -o "$SIGNED_IPA" "$OUTPUT_IPA"
    echo "  zsign: $SIGNED_IPA"
    OUTPUT_IPA="$SIGNED_IPA"
else
    echo "  [WARN] zsign not found, using ldid-signed IPA"
fi

echo ""
echo "=== PHASE 4: Install on device ==="
# Use ideviceinstaller.exe from palera1n-windows directory (see doc/BUILD_SIGN_INSTALL.md)
WIN_IPA=$(wslpath -w "$OUTPUT_IPA" 2>/dev/null || echo "$OUTPUT_IPA")
IDEVICE_INSTALLER='/mnt/c/Users/smolk/Documents/palera1n-windows/ideviceinstaller.exe'

if [ -f "$IDEVICE_INSTALLER" ]; then
    echo "  Installing via ideviceinstaller.exe..."
    "$IDEVICE_INSTALLER" -i "$OUTPUT_IPA" 2>&1 || {
        rc=$?
        echo "  [!] ideviceinstaller exit code $rc (exit 1 with Install: Complete is OK)"
    }
else
    echo "  [!] ideviceinstaller.exe not found at: $IDEVICE_INSTALLER"
    echo "  Install manually:"
    echo "    Windows IPA: $WIN_IPA" 
    echo "    Use: ideviceinstaller / 3uTools / iMazing"
fi

echo ""
echo "============================================"
echo " ALL DONE — Build 49"
echo " IPA: $OUTPUT_IPA"
echo "============================================"
