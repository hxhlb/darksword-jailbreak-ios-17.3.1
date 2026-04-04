#!/bin/bash
# build_and_inject.sh — Build darksword.framework and inject into Dopamine IPA
#
# Based on rooootdev/lara scripts/build_ipa.sh approach.
#
# Usage:
#   ./build_and_inject.sh                              # Build framework only
#   ./build_and_inject.sh /path/to/Dopamine.ipa        # Build + inject into IPA
#
# Requirements: macOS, Xcode 15+, ldid (for signing with entitlements)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOPAMINE_SRC="${DOPAMINE_SRC:-$SCRIPT_DIR/../Dopamine}"
ENTITLEMENTS="$SCRIPT_DIR/Config/lara.entitlements"
INPUT_IPA="$1"

echo "============================================"
echo " DarkSword Build & Inject"
echo " (rooootdev/lara exploit + 3 bug fixes)"
echo "============================================"
echo ""

# Step 1: Build the framework
echo "[1/4] Building darksword.framework..."
cd "$SCRIPT_DIR"
make clean
make all DOPAMINE_SRC="$DOPAMINE_SRC"
echo ""

FRAMEWORK="$SCRIPT_DIR/build/darksword.framework"

if [ ! -d "$FRAMEWORK" ]; then
    echo "ERROR: Framework not built"
    exit 1
fi

echo "[+] Framework built: $FRAMEWORK"
file "$FRAMEWORK/darksword"

# Step 1.5: Sign with ldid if available
if command -v ldid &>/dev/null && [ -f "$ENTITLEMENTS" ]; then
    echo "[+] Signing with ldid..."
    ldid -S"$ENTITLEMENTS" "$FRAMEWORK/darksword"
    echo "[+] Signed with entitlements"
else
    echo "[!] ldid not found or entitlements missing, skipping signing"
fi
echo ""

# Step 2: If no IPA provided, we're done
if [ -z "$INPUT_IPA" ]; then
    echo "============================================"
    echo " Build complete (framework only)"
    echo " To inject into Dopamine IPA:"
    echo "   $0 /path/to/Dopamine.ipa"
    echo "============================================"
    exit 0
fi

if [ ! -f "$INPUT_IPA" ]; then
    echo "ERROR: IPA not found: $INPUT_IPA"
    exit 1
fi

# Step 3: Inject into IPA
echo "[2/4] Extracting IPA..."
WORK_DIR="$SCRIPT_DIR/build/ipa_work"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"
unzip -q "$INPUT_IPA"

APP_DIR=$(find Payload -name "*.app" -maxdepth 2 -type d | head -1)
if [ -z "$APP_DIR" ]; then
    echo "ERROR: No .app found in IPA"
    exit 1
fi

echo "[3/4] Injecting darksword.framework into $APP_DIR..."
mkdir -p "$APP_DIR/Frameworks"
cp -R "$FRAMEWORK" "$APP_DIR/Frameworks/"
echo "[+] Framework injected"
ls -la "$APP_DIR/Frameworks/darksword.framework/"
echo ""

# Step 4: Re-package
OUTPUT_IPA="$SCRIPT_DIR/build/Dopamine_DarkSword.ipa"
echo "[4/4] Packaging modified IPA..."
cd "$WORK_DIR"
zip -r -q "$OUTPUT_IPA" Payload
rm -rf "$WORK_DIR"

echo ""
echo "============================================"
echo " Build & Inject COMPLETE"
echo " Output: $OUTPUT_IPA"
echo " Size:   $(du -h "$OUTPUT_IPA" | cut -f1)"
echo ""
echo " Install with TrollStore or SideStore"
echo "============================================"
