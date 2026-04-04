#!/bin/bash
# build_wsl.sh — Build darksword.framework and inject into Dopamine IPA
# Uses Theos toolchain in WSL (no macOS/Xcode required)
set -e

export THEOS=/opt/theos
export PATH=/opt/theos/bin:$PATH

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

# === Toolchain ===
CC="/opt/theos/toolchain/linux/iphone/bin/clang"
LDID="/opt/theos/bin/ldid"
SDK="/opt/theos/sdks/iPhoneOS16.5.sdk"

ARCH="arm64e"
MIN_IOS="17.0"
FRAMEWORK="darksword"

# === Flags ===
CFLAGS="-arch $ARCH \
  -miphoneos-version-min=$MIN_IOS \
  -isysroot $SDK \
  -I$SCRIPT_DIR/darksword \
  -fobjc-arc \
  -fvisibility=hidden \
  -fno-modules \
  -O2 \
  -DNDEBUG \
  -DDOPAMINE_INTEGRATION \
  -Wno-unused-function \
  -target arm64e-apple-ios${MIN_IOS}"

LDFLAGS="-shared \
  -arch $ARCH \
  -isysroot $SDK \
  -target arm64e-apple-ios${MIN_IOS} \
  -framework Foundation \
  -framework IOKit \
  -framework IOSurface \
  -Wl,-undefined,dynamic_lookup \
  -install_name @rpath/${FRAMEWORK}.framework/${FRAMEWORK}"

ENTITLEMENTS="$SCRIPT_DIR/Config/lara.entitlements"

# === Sources ===
SRCS=(
  darksword/darksword_exploit.m
  darksword/darksword_core.m
  darksword/utils.m
  darksword/kfs.m
  darksword/postexploit.m
  darksword/trustcache.m
  darksword/bootstrap.m
  darksword/filelog.m
)

echo "============================================"
echo " DarkSword WSL Build (Theos toolchain)"
echo " Arch: $ARCH | Min iOS: $MIN_IOS"
echo " SDK:  $SDK"
echo " CC:   $CC"
echo "============================================"
echo ""

# === Clean & prep ===
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# === Compile ===
OBJS=()
cd "$SCRIPT_DIR"
for src in "${SRCS[@]}"; do
    base=$(basename "$src" .m)
    obj="$BUILD_DIR/${base}.o"
    echo "[CC] $src → $obj"
    $CC $CFLAGS -c "$src" -o "$obj"
    OBJS+=("$obj")
done
echo ""

# === Link ===
PRODUCT="$BUILD_DIR/${FRAMEWORK}.framework"
mkdir -p "$PRODUCT"

echo "[LD] Linking ${FRAMEWORK}.framework..."
$CC $LDFLAGS -o "$PRODUCT/$FRAMEWORK" "${OBJS[@]}"

# Copy Info.plist
cp "$SCRIPT_DIR/darksword/Info.plist" "$PRODUCT/Info.plist"

file "$PRODUCT/$FRAMEWORK"
echo ""

# === Sign ===
if [ -x "$LDID" ] && [ -f "$ENTITLEMENTS" ]; then
    echo "[SIGN] ldid -S$ENTITLEMENTS"
    $LDID -S"$ENTITLEMENTS" "$PRODUCT/$FRAMEWORK"
    echo "[+] Signed with entitlements"
else
    echo "[!] Skipping signing (ldid=$LDID, ent=$ENTITLEMENTS)"
fi
echo ""

echo "=== Kernel framework built: $PRODUCT ==="
ls -la "$PRODUCT/"
echo ""

# ============================================================
# === Build darksword_ppl.framework (PPL Bypass Stub) ===
# ============================================================
# DarkSword's kernel exploit bypasses PPL via physical R/W.
# This stub satisfies Dopamine's requirement for a separate
# PPL exploit framework (DOEnvironmentManager.isPPLBypassRequired).

PPL_FRAMEWORK="darksword_ppl"
PPL_SRC="darksword_ppl/darksword_ppl.m"
PPL_PRODUCT="$BUILD_DIR/${PPL_FRAMEWORK}.framework"

echo "============================================"
echo " Building PPL Bypass Stub"
echo "============================================"

mkdir -p "$PPL_PRODUCT"

PPL_CFLAGS="-arch $ARCH \
  -miphoneos-version-min=$MIN_IOS \
  -isysroot $SDK \
  -fobjc-arc \
  -fvisibility=hidden \
  -fno-modules \
  -O2 \
  -DNDEBUG \
  -target arm64e-apple-ios${MIN_IOS}"

PPL_LDFLAGS="-shared \
  -arch $ARCH \
  -isysroot $SDK \
  -target arm64e-apple-ios${MIN_IOS} \
  -framework Foundation \
  -install_name @rpath/${PPL_FRAMEWORK}.framework/${PPL_FRAMEWORK}"

echo "[CC] $PPL_SRC"
$CC $PPL_CFLAGS -c "$SCRIPT_DIR/$PPL_SRC" -o "$BUILD_DIR/darksword_ppl.o"

echo "[LD] Linking ${PPL_FRAMEWORK}.framework..."
$CC $PPL_LDFLAGS -o "$PPL_PRODUCT/$PPL_FRAMEWORK" "$BUILD_DIR/darksword_ppl.o"

cp "$SCRIPT_DIR/darksword_ppl/Info.plist" "$PPL_PRODUCT/Info.plist"

file "$PPL_PRODUCT/$PPL_FRAMEWORK"

# Sign PPL framework
if [ -x "$LDID" ] && [ -f "$ENTITLEMENTS" ]; then
    echo "[SIGN] ldid -S$ENTITLEMENTS"
    $LDID -S"$ENTITLEMENTS" "$PPL_PRODUCT/$PPL_FRAMEWORK"
    echo "[+] PPL framework signed"
fi

echo "=== PPL framework built: $PPL_PRODUCT ==="
ls -la "$PPL_PRODUCT/"
echo ""

# === Inject into IPA ===
INPUT_IPA="$SCRIPT_DIR/Dopamine.ipa"
if [ ! -f "$INPUT_IPA" ]; then
    echo "[!] No Dopamine.ipa found — framework-only build complete."
    exit 0
fi

echo "[IPA] Extracting Dopamine.ipa..."
WORK_DIR="$BUILD_DIR/ipa_work"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"
unzip -q "$INPUT_IPA"

APP_DIR=$(find Payload -name "*.app" -maxdepth 2 -type d | head -1)
if [ -z "$APP_DIR" ]; then
    echo "ERROR: No .app found in IPA"
    exit 1
fi
echo "[IPA] Found: $APP_DIR"

# Inject both frameworks
echo "[IPA] Injecting darksword.framework (Kernel exploit)..."
mkdir -p "$APP_DIR/Frameworks"
cp -R "$PRODUCT" "$APP_DIR/Frameworks/"
ls -la "$APP_DIR/Frameworks/darksword.framework/"

echo "[IPA] Injecting darksword_ppl.framework (PPL bypass stub)..."
cp -R "$PPL_PRODUCT" "$APP_DIR/Frameworks/"
ls -la "$APP_DIR/Frameworks/darksword_ppl.framework/"
echo ""

# === Patch Dopamine binary: versionSupportString ===
# The hardcoded string "iOS 15.0 - 16.5.1 (arm64e)" in DOEnvironmentManager
# needs to reflect DarkSword's actual range (iOS 17.0-18.7).
# Replacement must be EXACT same byte length (27 chars).
DOPAMINE_BIN="$APP_DIR/Dopamine"
if [ -f "$DOPAMINE_BIN" ]; then
    echo "[PATCH] Patching versionSupportString in Dopamine binary..."
    python3 - "$DOPAMINE_BIN" << 'PYEOF'
import sys

binary_path = sys.argv[1]
with open(binary_path, 'rb') as f:
    data = f.read()

# Patch arm64e version string (must be same length = 27 bytes)
old_str = b'iOS 15.0 - 16.5.1 (arm64e)'
new_str = b'iOS 17.0 - 18.7   (arm64e)'

count = data.count(old_str)
if count > 0:
    data = data.replace(old_str, new_str)
    print(f"  [+] Patched arm64e string ({count} occurrence(s))")
else:
    print("  [!] arm64e version string not found (may be encrypted or different format)")

# Also patch arm64 string for completeness (44 bytes)
old_arm64 = b'iOS 15.0 - 15.8.6 / 16.0 - 16.6.1 (arm64)'
new_arm64 = b'iOS 15.0 - 18.7                     (arm64)'

count2 = data.count(old_arm64)
if count2 > 0:
    data = data.replace(old_arm64, new_arm64)
    print(f"  [+] Patched arm64 string ({count2} occurrence(s))")

with open(binary_path, 'wb') as f:
    f.write(data)

print("  [+] Binary patch complete")
PYEOF
    echo ""
else
    echo "[!] Dopamine binary not found at $DOPAMINE_BIN"
fi

echo "[IPA] Packaging..."
OUTPUT_IPA="$BUILD_DIR/Dopamine_DarkSword.ipa"
cd "$WORK_DIR"
zip -r -q "$OUTPUT_IPA" Payload
rm -rf "$WORK_DIR"

SIZE=$(du -h "$OUTPUT_IPA" | cut -f1)
echo ""
echo "============================================"
echo " BUILD COMPLETE"
echo ""
echo " Frameworks:"
echo "   darksword.framework     (Kernel exploit)"
echo "   darksword_ppl.framework (PPL bypass stub)"
echo ""
echo " IPA: $OUTPUT_IPA"
echo " Size: $SIZE"
echo ""
echo " Dopamine isSupported check:"
echo "   Kernel exploit: darksword ✓"
echo "   PAC bypass:     not required (iOS 15.2+) ✓"
echo "   PPL bypass:     darksword_ppl (stub) ✓"
echo ""
echo " Install via GBox / TrollStore / SideStore"
echo "============================================"
