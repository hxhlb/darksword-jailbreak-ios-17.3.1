#!/bin/bash
# Debug: run sign_app.py with verbose output
cd /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword

echo "=== Python test ==="
python3 -c "print('Python stdout works')"
python3 -c "import sys; print('stderr works', file=sys.stderr)"

echo "=== File check ==="
ls -la build_app/DarkSword.app/
echo "Info.plist exists: $(test -f build_app/DarkSword.app/Info.plist && echo YES || echo NO)"

echo "=== Sign ==="
python3 -u sign_app.py \
  build_app/DarkSword.app \
  cert.pem \
  key.pem \
  "ios (2) (2).mobileprovision"
echo "sign exit=$?"

echo "=== After sign ==="
ls -la build_app/DarkSword.app/
