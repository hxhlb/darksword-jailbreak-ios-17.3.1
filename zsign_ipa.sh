#!/bin/bash
set -e
ZSIGN='/mnt/c/Users/smolk/Documents/palera1n-windows/zsign_build/bin/zsign'
DS_DIR='/mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword'
IPA_IN="$DS_DIR/build_app/DarkSword.ipa"
IPA_OUT="$DS_DIR/build_app/DarkSword_signed.ipa"
P12="$DS_DIR/Сертификатыnew2 (3).p12"
MP="$DS_DIR/ios (2) (2).mobileprovision"
PASS='1984'

echo "[zsign] Signing IPA..."
"$ZSIGN" -k "$P12" -p "$PASS" -m "$MP" -b 'soft.ru.app' -o "$IPA_OUT" "$IPA_IN"
echo "[zsign] Done: $IPA_OUT"
ls -lh "$IPA_OUT"
