import plistlib, re, sys
with open(sys.argv[1], 'rb') as f:
    data = f.read()
m = re.search(b'<\\?xml.*?</plist>', data, re.DOTALL)
if m:
    pl = plistlib.loads(m.group(0))
    print('Name:', pl.get('Name',''))
    print('AppIDName:', pl.get('AppIDName',''))
    print('TeamName:', pl.get('TeamName',''))
    print('ExpirationDate:', pl.get('ExpirationDate',''))
    print('CreationDate:', pl.get('CreationDate',''))
    ents = pl.get('Entitlements', {})
    print('AppID:', ents.get('application-identifier',''))
    print('get-task-allow:', ents.get('get-task-allow',''))
    devs = pl.get('ProvisionedDevices', [])
    print('Devices:', len(devs))
    for d in devs[:5]: print(' ', d)
