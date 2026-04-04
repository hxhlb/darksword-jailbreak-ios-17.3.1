#!/bin/bash
cd /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword

MP="ios (2) (2).mobileprovision"
echo "=== MobileProvision Info ==="
python3 << 'PYEOF'
import plistlib
import sys

mp_path = "/mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword/ios (2) (2).mobileprovision"
mp_data = open(mp_path, 'rb').read()
s = mp_data.find(b'<?xml')
e = mp_data.find(b'</plist>') + 8
p = plistlib.loads(mp_data[s:e])

print(f"AppIDName: {p.get('AppIDName')}")
print(f"ApplicationIdentifierPrefix: {p.get('ApplicationIdentifierPrefix')}")
print(f"ExpirationDate: {p.get('ExpirationDate')}")
print(f"CreationDate: {p.get('CreationDate')}")
print(f"Platform: {p.get('Platform')}")
print(f"TeamName: {p.get('TeamName')}")
print(f"TimeToLive: {p.get('TimeToLive')}")
print(f"Version: {p.get('Version')}")

ents = p.get('Entitlements', {})
print(f"\nEntitlements.application-identifier: {ents.get('application-identifier')}")
print(f"Entitlements.get-task-allow: {ents.get('get-task-allow')}")

devices = p.get('ProvisionedDevices', [])
print(f"\nProvisioned devices ({len(devices)}):")
for d in devices:
    print(f"  {d}")
PYEOF
