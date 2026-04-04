#!/bin/bash
set -e
cd '/mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword'

echo "=== Extracting cert and key ==="
openssl pkcs12 -in 'Сертификатыnew2 (3).p12' -passin pass:1984 -legacy -nokeys -clcerts -out cert.pem 2>&1
openssl pkcs12 -in 'Сертификатыnew2 (3).p12' -passin pass:1984 -legacy -nocerts -nodes -out key.pem 2>&1
echo "Done"
ls -la cert.pem key.pem

echo ""
echo "=== Parsing mobileprovision ==="
python3 << 'PYEOF'
import plistlib
data = open('ios (2) (2).mobileprovision', 'rb').read()
start = data.find(b'<?xml')
end = data.find(b'</plist>') + len(b'</plist>')
if start >= 0 and end > start:
    plist = plistlib.loads(data[start:end])
    print('AppIDName:', plist.get('AppIDName','?'))
    print('TeamID:', plist.get('TeamIdentifier',['?']))
    ents = plist.get('Entitlements',{})
    print('BundleID:', ents.get('application-identifier','?'))
    print('TeamName:', plist.get('TeamName','?'))
    print('Expires:', plist.get('ExpirationDate','?'))
    devs = plist.get('ProvisionedDevices',[])
    print('ProvisionedDevices:', len(devs))
    if devs:
        for d in devs[:5]:
            print('  ', d)
    print('get-task-allow:', ents.get('get-task-allow','?'))
    # Save entitlements for signing
    import plistlib as pl
    with open('mp_entitlements.plist', 'wb') as f:
        pl.dump(ents, f)
    print('Entitlements saved to mp_entitlements.plist')
else:
    print('No plist found')
PYEOF
