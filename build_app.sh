#!/bin/bash
# build_app.sh — Build DarkSword standalone jailbreak app
# Uses Theos toolchain in WSL. NO Dopamine dependency.
set -e

export THEOS=/opt/theos
export PATH=/opt/theos/bin:$PATH

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build_app"

# === Toolchain ===
CC="/opt/theos/toolchain/linux/iphone/bin/clang"
LDID="/opt/theos/bin/ldid"
SDK="/opt/theos/sdks/iPhoneOS16.5.sdk"

# Build as arm64 (NOT arm64e) — runs fine on A12Z in compat mode,
# avoids ABI incompatibility with L1ghtmann clang on iOS 17
ARCH="arm64"
MIN_IOS="17.0"
APP_NAME="DarkSword"

echo "============================================"
echo " DarkSword Standalone App Build"
echo " Arch: $ARCH | Min iOS: $MIN_IOS"
echo " SDK:  $SDK"
echo " CC:   $CC"
echo "============================================"
echo ""

# === Flags ===
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

# Link as executable (not shared lib)
LDFLAGS="-arch $ARCH \
  -isysroot $SDK \
  -target arm64-apple-ios${MIN_IOS} \
  -framework Foundation \
  -framework UIKit \
  -framework IOKit \
  -framework IOSurface \
  -framework CoreGraphics \
  -e _main"

ENTITLEMENTS="$SCRIPT_DIR/app/entitlements.plist"

# === Sources — app + all darksword modules ===
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
echo "[LD] Linking $APP_NAME..."
$CC $LDFLAGS -o "$BUILD_DIR/$APP_NAME" "${OBJS[@]}"
file "$BUILD_DIR/$APP_NAME"
echo ""

# === Create .app bundle ===
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
mkdir -p "$APP_BUNDLE"

cp "$BUILD_DIR/$APP_NAME" "$APP_BUNDLE/$APP_NAME"
cp "$SCRIPT_DIR/app/Info.plist" "$APP_BUNDLE/Info.plist"

# Copy app icons
for icon in "$SCRIPT_DIR"/app/AppIcon*.png; do
  if [ -f "$icon" ]; then
    cp "$icon" "$APP_BUNDLE/"
  fi
done

# Compile LaunchScreen.storyboard to .storyboardc
# Since we can't use ibtool in WSL, create a minimal NIB placeholder
# iOS will still launch without a compiled storyboard if we provide
# a LaunchScreen key — worst case it just shows a black screen briefly
mkdir -p "$APP_BUNDLE/Base.lproj/LaunchScreen.storyboardc"
cp "$SCRIPT_DIR/app/LaunchScreen.storyboard" \
   "$APP_BUNDLE/Base.lproj/LaunchScreen.storyboardc/LaunchScreen.storyboard"

# === Sign ===
if [ -x "$LDID" ] && [ -f "$ENTITLEMENTS" ]; then
    echo "[SIGN] ldid -S$ENTITLEMENTS $APP_BUNDLE/$APP_NAME"
    $LDID -S"$ENTITLEMENTS" "$APP_BUNDLE/$APP_NAME"
    echo "[+] Signed with entitlements"
else
    echo "[!] ldid or entitlements not found!"
    exit 1
fi
echo ""

# === Verify ===
echo "=== App bundle contents ==="
ls -la "$APP_BUNDLE/"
file "$APP_BUNDLE/$APP_NAME"
echo ""

# === Package IPA ===
IPA_DIR="$BUILD_DIR/ipa_payload"
mkdir -p "$IPA_DIR/Payload"
cp -R "$APP_BUNDLE" "$IPA_DIR/Payload/"

OUTPUT_IPA="$BUILD_DIR/$APP_NAME.ipa"
cd "$IPA_DIR"
zip -r -q "$OUTPUT_IPA" Payload
rm -rf "$IPA_DIR"

SIZE=$(du -h "$OUTPUT_IPA" | cut -f1)
echo "============================================"
echo " BUILD COMPLETE"
echo ""
echo " App:  $APP_NAME.app"
echo " Arch: $ARCH (compatible with arm64e devices)"
echo " IPA:  $OUTPUT_IPA"
echo " Size: $SIZE"
echo ""
echo " Install via GBox / TrollStore / SideStore"
echo ""
echo " Features:"
echo "   - Standalone (no Dopamine dependency)"
echo "   - One-tap jailbreak button"
echo "   - Live log display"
echo "   - File logging: Documents/darksword_log.txt"
echo "   - UIFileSharingEnabled (access log via Files.app)"
echo "============================================"
