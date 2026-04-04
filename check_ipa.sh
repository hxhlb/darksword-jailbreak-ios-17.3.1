#!/bin/bash
cd /tmp
rm -rf ipa_check && mkdir ipa_check && cd ipa_check
cp '/mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword/build_app/DarkSword.ipa' .
unzip -q DarkSword.ipa
echo "=== App contents ==="
ls -la Payload/DarkSword.app/
echo "=== Info.plist ==="
python3 -c "
import plistlib
with open('Payload/DarkSword.app/Info.plist','rb') as f:
    p=plistlib.load(f)
for k in ['CFBundleIdentifier','MinimumOSVersion','CFBundleExecutable','CFBundleVersion']:
    print(k,'=',p.get(k,'MISSING'))
"
echo "=== mobileprovision exists ==="
ls -la Payload/DarkSword.app/embedded.mobileprovision 2>/dev/null || echo "MISSING!"
echo "=== _CodeSignature ==="
ls -la Payload/DarkSword.app/_CodeSignature/ 2>/dev/null || echo "MISSING!"
echo "=== Binary arch ==="
file Payload/DarkSword.app/DarkSword
